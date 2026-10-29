//! Qt Installer Framework (IFW) installers.
//!
//! The installer's metadata, such as its `config.xml`, is stored in Qt resource files that are
//! appended to the executable, which are found from a trailer at the end of the binary content.
//!
//! <https://github.com/qtproject/installer-framework/blob/master/src/libs/installer/binarycontent.cpp>

use std::{
    collections::BTreeSet,
    io::{self, Read, Seek, SeekFrom},
};

use flate2::read::ZlibDecoder;
use serde::Deserialize;
use thiserror::Error;
use tracing::debug;
use winget_types::{
    Version,
    installer::{
        AppsAndFeaturesEntry, Architecture, ExpectedReturnCode, InstallModes, InstallationMetadata,
        Installer, InstallerReturnCode, InstallerType, ReturnResponse, Switches,
    },
};
use zerocopy::{LE, U64};

use super::{
    pe::PE,
    utils::{
        RELATIVE_LOCAL_APP_DATA, RELATIVE_PROGRAM_FILES_32, RELATIVE_PROGRAM_FILES_64,
        RELATIVE_SYSTEM_DRIVE,
    },
};
use crate::{analysis::Installers, read::ReadBytesExt, traits::IntoWingetArchitecture};

/// The magic cookie at the end of an IFW binary's content, which can be followed by a signature.
const MAGIC_COOKIE: u64 = 0xc263_0a1c_99d6_68f8;

/// The magic marker of an installer, rather than a maintenance tool.
const MAGIC_INSTALLER_MARKER: u64 = 0x1202_3233;

/// The maximum distance from the end of the file that IFW searches for the magic cookie.
const MAX_COOKIE_SEARCH: u64 = 1 << 20;

/// The maximum size of a meta resource that's read into memory.
const MAX_META_RESOURCE_SIZE: u64 = 1 << 26;

const CONFIG_XML: &str = "/installer-config/config.xml";

#[derive(Error, Debug)]
pub enum QtIfwError {
    #[error("File is not a Qt Installer Framework installer")]
    NotQtIfwFile,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// <https://doc.qt.io/qtinstallerframework/ifw-globalconfig.html>
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Config {
    name: Option<String>,
    version: Option<String>,
    publisher: Option<String>,
    target_dir: Option<String>,
    #[serde(rename = "ProductUUID")]
    product_uuid: Option<String>,
}

pub struct QtIfw {
    architecture: Architecture,
    config: Config,
}

impl QtIfw {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, QtIfwError> {
        let end_of_binary_content = find_magic_cookie(&mut reader)?
            .ok_or(QtIfwError::NotQtIfwFile)?
            + size_of::<u64>() as u64;

        // The trailer ends with the meta resources count, the resource collections segment, the
        // meta resource segments, the operations segment, the resources count, the binary content
        // size, the magic marker and the magic cookie
        let read_u64_at = |reader: &mut R, offset: u64| -> io::Result<u64> {
            reader.seek(SeekFrom::Start(offset))?;
            Ok(reader.read_t::<U64<LE>>()?.get())
        };

        let u64_size = size_of::<u64>() as u64;
        let magic_marker = read_u64_at(&mut reader, end_of_binary_content - 2 * u64_size)?;
        if magic_marker != MAGIC_INSTALLER_MARKER {
            return Err(QtIfwError::NotQtIfwFile);
        }

        let binary_content_size = read_u64_at(&mut reader, end_of_binary_content - 3 * u64_size)?;
        let meta_resources_count = read_u64_at(&mut reader, end_of_binary_content - 4 * u64_size)?;
        let end_of_executable = end_of_binary_content
            .checked_sub(binary_content_size)
            .ok_or(QtIfwError::NotQtIfwFile)?;

        // Skip the resource collections segment
        let meta_resource_segments_offset = meta_resources_count
            .checked_mul(2 * u64_size)
            .and_then(|size| end_of_binary_content.checked_sub(size + 8 * u64_size))
            .ok_or(QtIfwError::NotQtIfwFile)?
            + 2 * u64_size;

        let mut config = None;
        for index in 0..meta_resources_count {
            let segment_offset = meta_resource_segments_offset + index * 2 * u64_size;
            let start = read_u64_at(&mut reader, segment_offset)?;
            let length = reader.read_t::<U64<LE>>()?.get();
            if length > MAX_META_RESOURCE_SIZE {
                continue;
            }

            reader.seek(SeekFrom::Start(end_of_executable + start))?;
            let mut resource = vec![0; length as usize];
            reader.read_exact(&mut resource)?;

            if let Some(config_xml) = read_qt_resource(&resource, CONFIG_XML) {
                config = quick_xml::de::from_str::<Config>(&String::from_utf8_lossy(&config_xml))
                    .inspect_err(|error| debug!(%error, "Failed to parse config.xml"))
                    .ok();
                break;
            }
        }

        let config = config.ok_or(QtIfwError::NotQtIfwFile)?;
        debug!(?config);

        Ok(Self {
            architecture: pe.winget_architecture(),
            config,
        })
    }

    /// Resolves the predefined variables in the target directory.
    ///
    /// <https://doc.qt.io/qtinstallerframework/scripting-installer.html#value-method>
    fn install_directory(&self) -> Option<String> {
        let mut directory = self.config.target_dir.clone()?;
        let applications_dir = if self.architecture.is_64_bit() {
            RELATIVE_PROGRAM_FILES_64
        } else {
            RELATIVE_PROGRAM_FILES_32
        };
        let applications_dir_user = format!(r"{RELATIVE_LOCAL_APP_DATA}\Programs");

        for (variable, value) in [
            ("@ApplicationsDirX86@", RELATIVE_PROGRAM_FILES_32),
            ("@ApplicationsDirX64@", RELATIVE_PROGRAM_FILES_64),
            ("@ApplicationsDirUser@", &applications_dir_user),
            ("@ApplicationsDir@", applications_dir),
            ("@HomeDir@", "%UserProfile%"),
            ("@RootDir@", RELATIVE_SYSTEM_DRIVE),
            ("@Name@", self.config.name.as_deref().unwrap_or("@Name@")),
            (
                "@Publisher@",
                self.config.publisher.as_deref().unwrap_or("@Publisher@"),
            ),
        ] {
            directory = directory.replace(variable, value);
        }

        // Ignore directories with variables that aren't known, and relative directories, which
        // are set by the installer's scripts instead
        let is_absolute = directory.starts_with('%')
            || directory
                .as_bytes()
                .get(..2)
                .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1] == b':');
        (is_absolute && !directory.contains('@')).then(|| directory.replace('/', r"\"))
    }
}

impl Installers for QtIfw {
    fn installers(&self) -> Vec<Installer> {
        let install_directory = self.install_directory();

        vec![Installer {
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            // The uninstall key is written to HKCU unless the `AllUsers` variable is set, which
            // is independent of the target directory
            install_modes: InstallModes::all(),
            // https://doc.qt.io/qtinstallerframework/ifw-cli.html
            switches: Switches::builder()
                .silent(
                    "install --accept-licenses --accept-messages --confirm-command --default-answer"
                        .parse()
                        .unwrap(),
                )
                .silent_with_progress(
                    "install --accept-licenses --accept-messages --confirm-command --default-answer"
                        .parse()
                        .unwrap(),
                )
                .install_location(r#"--root "<INSTALLPATH>""#.parse().unwrap())
                .build(),
            expected_return_codes: expected_return_codes(),
            product_code: self.config.product_uuid.clone(),
            apps_and_features_entries: AppsAndFeaturesEntry::builder()
                .maybe_display_name(self.config.name.as_deref())
                .maybe_publisher(self.config.publisher.as_deref())
                .maybe_display_version(
                    self.config
                        .version
                        .as_deref()
                        .and_then(|version| version.parse::<Version>().ok()),
                )
                .maybe_product_code(self.config.product_uuid.as_deref())
                .build()
                .into(),
            installation_metadata: InstallationMetadata::new_install_location(
                install_directory.map(winget_types::PathBuf::from),
            ),
            ..Installer::default()
        }]
    }
}

/// <https://doc.qt.io/qtinstallerframework/qinstaller-packagemanagercore.html#Status-enum>
fn expected_return_codes() -> BTreeSet<ExpectedReturnCode> {
    [
        (1, ReturnResponse::ContactSupport),
        (2, ReturnResponse::InstallInProgress),
        (3, ReturnResponse::CancelledByUser),
    ]
    .into_iter()
    .filter_map(|(code, response)| {
        InstallerReturnCode::new(code).map(|code| ExpectedReturnCode::new(code, response))
    })
    .collect()
}

/// Returns the file offset of the last magic cookie in the last megabyte of the file.
fn find_magic_cookie<R: Read + Seek>(mut reader: R) -> io::Result<Option<u64>> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let search_size = file_size.min(MAX_COOKIE_SEARCH);
    let search_start = file_size - search_size;

    reader.seek(SeekFrom::Start(search_start))?;
    let mut data = Vec::with_capacity(search_size as usize);
    reader.take(search_size).read_to_end(&mut data)?;

    Ok(memchr::memmem::rfind(&data, &MAGIC_COOKIE.to_le_bytes())
        .map(|position| search_start + position as u64))
}

/// Reads a file from a Qt resource (`.rcc`) file.
///
/// <https://github.com/qt/qtbase/blob/dev/src/corelib/io/qresource.cpp>
fn read_qt_resource(data: &[u8], path: &str) -> Option<Vec<u8>> {
    const DIRECTORY: u16 = 0x02;
    const COMPRESSED: u16 = 0x01;

    let read_u16 = |offset: usize| -> Option<u16> {
        Some(u16::from_be_bytes(
            data.get(offset..offset + 2)?.try_into().ok()?,
        ))
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        Some(u32::from_be_bytes(
            data.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };

    if data.get(..4)? != b"qres" {
        return None;
    }

    let version = read_u32(4)?;
    let tree = read_u32(8)? as usize;
    let payloads = read_u32(12)? as usize;
    let names = read_u32(16)? as usize;
    let node_size = if version >= 2 { 22 } else { 14 };

    let name = |offset: u32| -> Option<String> {
        let offset = names + offset as usize;
        let length = usize::from(read_u16(offset)?);
        let units = data
            .get(offset + 6..offset + 6 + length * 2)?
            .chunks_exact(2)
            .map(|unit| u16::from_be_bytes([unit[0], unit[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&units).ok()
    };

    // Walk down the tree, starting at the root directory
    let mut node = tree;
    for component in path.trim_start_matches('/').split('/') {
        if read_u16(node + 4)? & DIRECTORY == 0 {
            return None;
        }
        let child_count = read_u32(node + 6)?;
        let first_child = read_u32(node + 10)?;
        node = (first_child..first_child + child_count)
            .map(|index| tree + index as usize * node_size)
            .find(|&child| read_u32(child).and_then(name).as_deref() == Some(component))?;
    }

    let flags = read_u16(node + 4)?;
    if flags & DIRECTORY != 0 {
        return None;
    }

    let payload = payloads + read_u32(node + 10)? as usize;
    let size = read_u32(payload)? as usize;
    let content = data.get(payload + 4..payload + 4 + size)?;

    if flags & COMPRESSED != 0 {
        // Compressed content is prefixed with its uncompressed size
        let mut decompressed = Vec::new();
        ZlibDecoder::new(content.get(4..)?)
            .read_to_end(&mut decompressed)
            .ok()?;
        Some(decompressed)
    } else {
        Some(content.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use winget_types::installer::Architecture;

    use super::{Config, QtIfw};

    fn qt_ifw(target_dir: &str, architecture: Architecture) -> QtIfw {
        QtIfw {
            architecture,
            config: Config {
                name: Some("App".to_owned()),
                publisher: Some("Vendor".to_owned()),
                target_dir: Some(target_dir.to_owned()),
                ..Config::default()
            },
        }
    }

    #[rstest]
    #[case(
        "@ApplicationsDirX86@/XaoS",
        Architecture::X64,
        Some(r"%ProgramFiles(x86)%\XaoS")
    )]
    #[case(
        "@ApplicationsDir@/App",
        Architecture::X64,
        Some(r"%ProgramFiles%\App")
    )]
    #[case(
        "@ApplicationsDir@/App",
        Architecture::X86,
        Some(r"%ProgramFiles(x86)%\App")
    )]
    #[case("@HomeDir@/HexWalk", Architecture::X64, Some(r"%UserProfile%\HexWalk"))]
    #[case(
        "@ApplicationsDirUser@/@Publisher@/@Name@",
        Architecture::X64,
        Some(r"%LocalAppData%\Programs\Vendor\App")
    )]
    #[case("C:/msys64", Architecture::X64, Some(r"C:\msys64"))]
    #[case("nul", Architecture::X86, None)]
    #[case("@UnknownDir@/App", Architecture::X64, None)]
    fn resolves_target_dir(
        #[case] target_dir: &str,
        #[case] architecture: Architecture,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(
            qt_ifw(target_dir, architecture)
                .install_directory()
                .as_deref(),
            expected
        );
    }
}
