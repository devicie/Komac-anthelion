//! Microsoft's self-extracting cabinets (SFXCAB), such as the Visual C++ 2008 and 2010
//! redistributables and the Visual Studio Tools for Office runtime.
//!
//! The cabinet is stored at the start of the `.rsrc` section, after the resources. After extracting
//! it, the command in the `_sfx_manifest_` file in the cabinet is run, if there is one.

use std::io::{self, Read, Seek, SeekFrom};

use cab::Cabinet;
use memchr::memmem;
use thiserror::Error;
use tracing::debug;
use winget_types::installer::{Architecture, Installer, InstallerType, Switches};
use zerocopy::LE;

use super::{
    msi::Msi,
    pe::{PE, VSVersionInfo, resource::SectionReader},
    utils::cabinet::{file_names, is_msi, read_msi, trim_current_dir},
};
use crate::{analysis::Installers, read::ReadBytesExt, traits::IntoWingetArchitecture};

const RSRC: [u8; 8] = *b".rsrc\0\0\0";

/// The original file name in the version info of the self-extractor.
const SFXCAB: &str = "sfxcab";

/// The cabinet signature followed by the reserved field, which is always zero.
const CABINET_SIGNATURE: &[u8; 8] = b"MSCF\0\0\0\0";

/// The maximum distance from the start of the `.rsrc` section to search for the cabinet.
const MAX_CABINET_SEARCH: u32 = 1 << 20;

const SFX_MANIFEST: &str = "_sfx_manifest_";
const SFX_CAB_EXE_PATH: &str = r"%_SFX_CAB_EXE_PATH%\";
const SFX_CAB_EXE_PARAMETERS: &str = "%_SFX_CAB_EXE_PARAMETERS%";

/// The setup chainer used by the Visual C++ 2010 redistributables and later .NET Framework 4
/// installers, which is configured by `ParameterInfo.xml`.
const SETUP_EXE: &str = "Setup.exe";
const PARAMETER_INFO_XML: &str = "ParameterInfo.xml";

/// The Visual Studio 2008 setup bootstrapper.
const INSTALL_EXE: &str = "install.exe";

/// The Windows update installer used by hotfixes.
const UPDATE_EXE: &str = r"update\update.exe";

const MSIEXEC: &str = "msiexec";

#[derive(Error, Debug)]
pub enum SfxCabError {
    #[error("File is not a self-extracting cabinet")]
    NotSfxCabFile,
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Bootstrapper {
    /// The setup chainer configured by `ParameterInfo.xml`.
    SetupChainer,
    /// The Visual Studio 2008 setup bootstrapper.
    VisualStudio2008,
    /// The Windows update installer used by hotfixes.
    Hotfix,
    Msiexec,
    Unknown,
}

pub struct SfxCab {
    architecture: Architecture,
    bootstrapper: Bootstrapper,
    msi: Option<Msi>,
}

impl SfxCab {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, SfxCabError> {
        if !is_sfxcab(&mut reader, pe) {
            return Err(SfxCabError::NotSfxCabFile);
        }

        let rsrc = pe.find_section(RSRC).ok_or(SfxCabError::NotSfxCabFile)?;
        let cabinet_offset = find_cabinet(
            &mut reader,
            rsrc.pointer_to_raw_data(),
            rsrc.size_of_raw_data(),
        )?
        .ok_or(SfxCabError::NotSfxCabFile)?;

        reader.seek(SeekFrom::Start(cabinet_offset + 8))?;
        let cabinet_size = reader.read_u32::<LE>()?;

        let mut cabinet = Cabinet::new(SectionReader::new(
            &mut reader,
            cabinet_offset,
            cabinet_size.into(),
        )?)?;

        let file_names = file_names(&cabinet);

        let command = file_names
            .iter()
            .find(|name| trim_current_dir(name).eq_ignore_ascii_case(SFX_MANIFEST))
            .cloned()
            .and_then(|name| {
                let mut manifest = String::new();
                cabinet
                    .read_file(&name)
                    .ok()?
                    .read_to_string(&mut manifest)
                    .ok()?;
                command_from_manifest(&manifest).map(str::to_owned)
            });

        debug!(?command, ?file_names);

        let has_file = |file_name: &str| {
            file_names
                .iter()
                .any(|name| trim_current_dir(name).eq_ignore_ascii_case(file_name))
        };

        let bootstrapper = match command.as_deref() {
            // Switches can only be used if the command line is passed through
            Some(command) if !command.contains(SFX_CAB_EXE_PARAMETERS) => Bootstrapper::Unknown,
            Some(command) => match program_name(command) {
                Some(program)
                    if program.eq_ignore_ascii_case(SETUP_EXE) && has_file(PARAMETER_INFO_XML) =>
                {
                    Bootstrapper::SetupChainer
                }
                Some(program)
                    if program
                        .get(..MSIEXEC.len())
                        .is_some_and(|name| name.eq_ignore_ascii_case(MSIEXEC)) =>
                {
                    Bootstrapper::Msiexec
                }
                _ => Bootstrapper::Unknown,
            },
            None if has_file(INSTALL_EXE) => Bootstrapper::VisualStudio2008,
            None if has_file(UPDATE_EXE) => Bootstrapper::Hotfix,
            None => Bootstrapper::Unknown,
        };

        // Only use an MSI if it's clearly the product, rather than one of several prerequisites
        let mut msis = file_names.iter().filter(|name| is_msi(name));
        let msi = match (msis.next(), msis.next()) {
            (Some(msi), None) => read_msi(&mut cabinet, &msi.clone()),
            _ => None,
        };

        Ok(Self {
            architecture: msi
                .as_ref()
                .map_or_else(|| pe.winget_architecture(), |msi| msi.architecture),
            bootstrapper,
            msi,
        })
    }
}

impl Installers for SfxCab {
    fn installers(&self) -> Vec<Installer> {
        // The command line is passed through to the command that is run after extracting
        let switches = match self.bootstrapper {
            Bootstrapper::SetupChainer => setup_chainer_switches(),
            Bootstrapper::VisualStudio2008 => Switches::builder()
                .silent("/q".parse().unwrap())
                .silent_with_progress("/qb".parse().unwrap())
                .build(),
            Bootstrapper::Hotfix | Bootstrapper::Msiexec => Switches::builder()
                .silent("/quiet /norestart".parse().unwrap())
                .silent_with_progress("/passive /norestart".parse().unwrap())
                .build(),
            Bootstrapper::Unknown => Switches::default(),
        };

        if let Some(msi) = &self.msi {
            return vec![msi.wrapped_installer(switches)];
        }

        vec![Installer {
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            switches,
            ..Installer::default()
        }]
    }
}

/// Returns the switches of the setup chainer, which is configured by `ParameterInfo.xml`.
pub fn setup_chainer_switches() -> Switches {
    Switches::builder()
        .silent("/q /norestart".parse().unwrap())
        .silent_with_progress("/passive /norestart".parse().unwrap())
        .log(r#"/log "<LOGPATH>""#.parse().unwrap())
        .build()
}

/// Returns `true` if any version info of the executable is that of the self-extractor.
fn is_sfxcab<R: Read + Seek>(reader: R, pe: &PE) -> bool {
    pe.vs_version_infos(reader).is_ok_and(|version_infos| {
        version_infos.iter().any(|version_info| {
            VSVersionInfo::read_from(version_info).is_ok_and(|version_info| {
                version_info
                    .string_entries()
                    .filter(|&(key, _)| key == "OriginalFilename" || key == "InternalName")
                    .any(|(_, value)| {
                        value
                            .trim()
                            .trim_end_matches(".exe")
                            .trim_end_matches(".EXE")
                            .eq_ignore_ascii_case(SFXCAB)
                    })
            })
        })
    })
}

/// Returns the file offset of the cabinet in the `.rsrc` section.
fn find_cabinet<R: Read + Seek>(
    mut reader: R,
    section_offset: u32,
    section_size: u32,
) -> io::Result<Option<u64>> {
    let mut data = Vec::new();
    reader.seek(SeekFrom::Start(section_offset.into()))?;
    reader
        .take(section_size.min(MAX_CABINET_SEARCH).into())
        .read_to_end(&mut data)?;

    Ok(memmem::find_iter(&data, CABINET_SIGNATURE)
        .find(|&position| {
            // The cabinet size must fit in the section
            data.get(position + 8..position + 12)
                .map(|size| u32::from_le_bytes(size.try_into().unwrap()))
                .is_some_and(|size| u64::from(size) <= u64::from(section_size) - position as u64)
        })
        .map(|position| u64::from(section_offset) + position as u64))
}

/// Returns the command in an `_sfx_manifest_`, without the extraction directory.
///
/// ```ini
/// [Options]
/// Command=%_SFX_CAB_EXE_PATH%\Setup.exe %_SFX_CAB_EXE_PARAMETERS%
/// ```
fn command_from_manifest(manifest: &str) -> Option<&str> {
    manifest.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("Command")
            .then(|| value.trim().trim_start_matches(SFX_CAB_EXE_PATH))
    })
}

/// Returns the program of a command.
/// Returns the file name of the program of a command.
fn program_name(command: &str) -> Option<&str> {
    let program = command.split_ascii_whitespace().next()?;
    program.rsplit(['\\', '/']).next()
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;

    use super::{command_from_manifest, program_name};

    #[test]
    fn command_from_sfx_manifest() {
        const MANIFEST: &str = indoc! {r"
            [Options]
            Command=%_SFX_CAB_EXE_PATH%\Setup.exe %_SFX_CAB_EXE_PARAMETERS%
        "};

        let command = command_from_manifest(MANIFEST).unwrap();
        assert_eq!(command, "Setup.exe %_SFX_CAB_EXE_PARAMETERS%");
        assert_eq!(program_name(command), Some("Setup.exe"));
    }

    #[rstest]
    #[case(
        r"%SYSTEMROOT%\system32\msiexec /i %_SFX_CAB_EXE_PATH%\msxml.msi",
        Some("msiexec")
    )]
    #[case(r"\Setup.exe %_SFX_CAB_EXE_PARAMETERS%", Some("Setup.exe"))]
    #[case(
        r"wcu\dotNetFramework\dotNetFx35setup.exe %_SFX_CAB_EXE_PARAMETERS%",
        Some("dotNetFx35setup.exe")
    )]
    #[case("", None)]
    fn program_name_from_command(#[case] command: &str, #[case] expected: Option<&str>) {
        assert_eq!(program_name(command), expected);
    }

    #[test]
    fn manifest_without_command() {
        assert_eq!(command_from_manifest("[Options]\r\n"), None);
    }
}
