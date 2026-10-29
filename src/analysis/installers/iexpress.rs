//! IExpress self-extractors, which are extracted by Wextract.
//!
//! The files are stored in a cabinet in the `CABINET` resource, and the command that is run after
//! extracting them is stored in the `RUNPROGRAM` resource.
//!
//! <https://learn.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms757993(v=vs.85)>

use std::io::{self, Read, Seek};

use cab::Cabinet;
use encoding_rs::WINDOWS_1252;
use thiserror::Error;
use tracing::debug;
use winget_types::installer::{Architecture, Installer, InstallerType, Switches};

use super::{
    msi::Msi,
    pe::PE,
    utils::cabinet::{file_names, is_msi, read_msi, trim_current_dir},
};
use crate::{analysis::Installers, traits::IntoWingetArchitecture};

const CABINET: &str = "CABINET";
const RUN_PROGRAM: &str = "RUNPROGRAM";
const ADMIN_QUIET_COMMAND: &str = "ADMQCMD";
const USER_QUIET_COMMAND: &str = "USRQCMD";

/// The value of a command resource that isn't set.
const NONE: &str = "<None>";

const MSIEXEC: &str = "msiexec";

#[derive(Error, Debug)]
pub enum IExpressError {
    #[error("File is not an IExpress installer")]
    NotIExpressFile,
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct IExpress {
    architecture: Architecture,
    run_program: String,
    has_quiet_command: bool,
    msi: Option<Msi>,
}

impl IExpress {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, IExpressError> {
        let run_program = read_command(&mut reader, pe, RUN_PROGRAM)
            .map_err(|_| IExpressError::NotIExpressFile)?
            .unwrap_or_default();

        let has_quiet_command = [ADMIN_QUIET_COMMAND, USER_QUIET_COMMAND]
            .iter()
            .any(|name| matches!(read_command(&mut reader, pe, name), Ok(Some(_))));

        let mut cabinet = Cabinet::new(
            pe.find_rc_data_by_name(&mut reader, CABINET)
                .map_err(|_| IExpressError::NotIExpressFile)?,
        )
        .map_err(|_| IExpressError::NotIExpressFile)?;

        let file_names = file_names(&cabinet);
        debug!(run_program, has_quiet_command, ?file_names);

        let msi = msi_name(&run_program)
            .and_then(|msi_name| {
                file_names
                    .iter()
                    .find(|name| trim_current_dir(name).eq_ignore_ascii_case(msi_name))
            })
            .and_then(|name| read_msi(&mut cabinet, name));

        Ok(Self {
            architecture: msi
                .as_ref()
                .map_or_else(|| pe.winget_architecture(), |msi| msi.architecture),
            run_program,
            has_quiet_command,
            msi,
        })
    }
}

impl Installers for IExpress {
    fn installers(&self) -> Vec<Installer> {
        // https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/command-line-switches-for-iexpress-packages
        if let Some(msi) = &self.msi {
            // `/C` replaces the command that is run, so the MSI can be installed silently
            let command = self.run_program.replace('"', r#""""#);
            let switches = Switches::builder()
                .silent(format!(r#"/Q /C:"{command} /quiet""#).parse().unwrap())
                .silent_with_progress(format!(r#"/Q /C:"{command} /passive""#).parse().unwrap())
                .build();
            return vec![msi.wrapped_installer(switches)];
        }

        vec![Installer {
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            // `/Q` runs the quiet command instead of the normal one, if there is one. Otherwise, the
            // normal command is run, which may not be silent.
            switches: if self.has_quiet_command {
                Switches::builder()
                    .silent("/Q".parse().unwrap())
                    .silent_with_progress("/Q".parse().unwrap())
                    .build()
            } else {
                Switches::default()
            },
            ..Installer::default()
        }]
    }
}

/// Reads a command from an `RCDATA` resource, returning [`None`] if it isn't set.
fn read_command<R: Read + Seek>(mut reader: R, pe: &PE, name: &str) -> io::Result<Option<String>> {
    let mut data = Vec::new();
    pe.find_rc_data_by_name(&mut reader, name)?
        .read_to_end(&mut data)?;

    let command = WINDOWS_1252.decode_without_bom_handling(&data).0;
    let command = command.trim_end_matches('\0').trim();

    Ok((!command.is_empty() && !command.eq_ignore_ascii_case(NONE)).then(|| command.to_owned()))
}

/// Returns the name of the MSI that a command installs, if it installs one.
fn msi_name(command: &str) -> Option<&str> {
    let mut arguments = command
        .split('"')
        .enumerate()
        .flat_map(|(index, part)| {
            // Every other part is quoted
            if index % 2 == 1 {
                vec![part]
            } else {
                part.split_ascii_whitespace().collect()
            }
        })
        .filter(|argument| !argument.is_empty());

    let program = arguments.next()?;
    let program_name = program.rsplit(['\\', '/']).next().unwrap_or(program);

    if is_msi(program_name) {
        return Some(program_name);
    }

    if !program_name
        .get(..MSIEXEC.len())
        .is_some_and(|name| name.eq_ignore_ascii_case(MSIEXEC))
    {
        return None;
    }

    arguments.find(|argument| is_msi(argument))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::msi_name;

    #[rstest]
    #[case("msiexec /i vcredist.msi", Some("vcredist.msi"))]
    #[case(r#"msiexec.exe /i "My Product.msi" /qb"#, Some("My Product.msi"))]
    #[case(r#"MSIEXEC /package "setup.MSI""#, Some("setup.MSI"))]
    #[case("product.msi", Some("product.msi"))]
    #[case(r#""dxwsetup.exe""#, None)]
    #[case("setup.exe /install product.msi", None)]
    #[case("", None)]
    fn msi_name_from_command(#[case] command: &str, #[case] expected: Option<&str>) {
        assert_eq!(msi_name(command), expected);
    }
}
