//! 7-Zip's installer SFX modules (`7zS.sfx` and `7zSD.sfx`), which extract a 7z archive and run a
//! program from it, passing their command line through to the program.
//!
//! The archive is preceded by a config in the overlay:
//!
//! ```text
//! ;!@Install@!UTF-8!
//! Title="Mozilla Firefox"
//! RunProgram="setup.exe"
//! ;!@InstallEnd@!
//! ```
//!
//! <https://github.com/ip7z/7zip/blob/main/CPP/7zip/Bundles/SFXSetup/SfxSetup.cpp>

use std::{
    io::{self, BufRead, BufReader, Cursor, Read, Seek, SeekFrom},
    mem,
};

use sevenz_rust2::{ArchiveReader, Password};
use thiserror::Error;
use tracing::debug;
use winget_types::installer::Installer;

use super::{
    font::FontAnalysis,
    pe::{PE, resource::SectionReader},
};
use crate::analysis::{Analyzer, Installers};

/// The config that precedes the 7z archive in the overlay is delimited by these lines.
const CONFIG_START: &[u8] = b";!@Install@!UTF-8!";
const CONFIG_END: &[u8] = b";!@InstallEnd@!";

const MAX_CONFIG_SIZE: u64 = 1 << 16;

/// The program that is run if the config doesn't specify one.
const DEFAULT_PROGRAM: &str = "setup.exe";

#[derive(Error, Debug)]
pub enum SevenZipSfxError {
    #[error("File is not a 7-Zip SFX installer")]
    NotSevenZipSfxFile,
    #[error("Failed to analyze {program} in the 7-Zip SFX installer")]
    Analysis {
        program: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error(transparent)]
    SevenZ(#[from] sevenz_rust2::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The config of a 7-Zip SFX module.
pub struct SfxConfig {
    pairs: Vec<(String, String)>,
    /// The file offset of the 7z archive.
    pub archive_offset: u64,
}

impl SfxConfig {
    /// Reads the config from the overlay, returning [`None`] if there isn't one.
    pub fn read<R: Read + Seek>(mut reader: R, pe: &PE) -> io::Result<Option<Self>> {
        let Some(overlay_offset) = pe.overlay_offset() else {
            return Ok(None);
        };

        reader.seek(SeekFrom::Start(overlay_offset))?;
        let mut config = BufReader::new(reader.take(MAX_CONFIG_SIZE));
        let mut config_size = 0;
        let mut pairs = Vec::new();
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = config.read_until(b'\n', &mut line)?;
            if read == 0 || (config_size == 0 && !line.starts_with(CONFIG_START)) {
                return Ok(None);
            }

            // The archive can follow the end of the config on the same line
            if let Some(rest) = line.strip_prefix(CONFIG_END) {
                let line_ending = rest
                    .iter()
                    .take_while(|&&byte| byte == b'\r' || byte == b'\n')
                    .count();
                config_size += (CONFIG_END.len() + line_ending) as u64;
                break;
            }

            config_size += read as u64;
            if let Some(pair) = parse_pair(&String::from_utf8_lossy(&line)) {
                pairs.push(pair);
            }
        }

        Ok(Some(Self {
            pairs,
            archive_offset: overlay_offset + config_size,
        }))
    }

    /// Returns the value of a key in the config.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// Returns the path of the program in the archive that's run after extracting it.
    fn program(&self) -> String {
        let command = self
            .get("ExecuteFile")
            .or_else(|| self.get("RunProgram"))
            .filter(|command| !command.trim().is_empty())
            .unwrap_or(DEFAULT_PROGRAM);
        program_path(command)
    }
}

/// Parses a `Key="Value"` line, unescaping the value the same way as 7-Zip.
///
/// <https://github.com/ip7z/7zip/blob/main/CPP/Common/TextConfig.cpp>
fn parse_pair(line: &str) -> Option<(String, String)> {
    let (key, value) = line.split_once('=')?;
    let mut chars = value.trim().strip_prefix('"')?.chars();
    let mut unescaped = String::new();
    loop {
        match chars.next()? {
            '"' => break,
            '\\' => match chars.next()? {
                'n' => unescaped.push('\n'),
                't' => unescaped.push('\t'),
                character @ ('\\' | '"') => unescaped.push(character),
                character => {
                    unescaped.push('\\');
                    unescaped.push(character);
                }
            },
            character => unescaped.push(character),
        }
    }
    Some((key.trim().to_owned(), unescaped))
}

/// Returns the path of a command's program relative to the archive, such as `setup.exe` from
/// `"%%T\setup.exe" /S`.
fn program_path(command: &str) -> String {
    let command = command.trim_start();
    let program = if let Some(quoted) = command.strip_prefix('"') {
        quoted.split('"').next().unwrap_or(quoted)
    } else {
        command.split_ascii_whitespace().next().unwrap_or(command)
    };

    let mut program = program.replace('\\', "/");
    for prefix in ["%%T/", "%T/", "./"] {
        while let Some(rest) = program.strip_prefix(prefix) {
            program = rest.to_owned();
        }
    }
    program
}

pub struct SevenZipSfx {
    installers: Vec<Installer>,
}

impl SevenZipSfx {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, SevenZipSfxError> {
        let config =
            SfxConfig::read(&mut reader, pe)?.ok_or(SevenZipSfxError::NotSevenZipSfxFile)?;

        let program = config.program();
        debug!(program);

        let mut archive = ArchiveReader::new(
            SectionReader::from_offset(&mut reader, config.archive_offset)?,
            Password::empty(),
        )
        .map_err(|_| SevenZipSfxError::NotSevenZipSfxFile)?;

        let Some(name) = archive
            .archive()
            .files
            .iter()
            .map(|entry| entry.name())
            .find(|name| name.replace('\\', "/").eq_ignore_ascii_case(&program))
            .map(str::to_owned)
        else {
            debug!("{program} isn't in the archive");
            return Err(SevenZipSfxError::NotSevenZipSfxFile);
        };

        // The command line is passed through to the program, so the program's installers apply
        let mut program_file = Cursor::new(archive.read_file(&name)?);
        let mut analyzer =
            Analyzer::new(&mut program_file, &name, FontAnalysis::None).map_err(|error| {
                SevenZipSfxError::Analysis {
                    program: name.clone(),
                    source: error.into(),
                }
            })?;

        Ok(Self {
            installers: mem::take(&mut analyzer.installers),
        })
    }
}

impl Installers for SevenZipSfx {
    fn installers(&self) -> Vec<Installer> {
        self.installers.clone()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{parse_pair, program_path};

    #[rstest]
    #[case(r#"RunProgram="setup.exe""#, "RunProgram", "setup.exe")]
    #[case(
        r#"RunProgram="RECentral_Installer\REC\setup.exe""#,
        "RunProgram",
        r"RECentral_Installer\REC\setup.exe"
    )]
    #[case(
        r#"RunProgram="\"%%T\\setup.exe\" /S""#,
        "RunProgram",
        r#""%%T\setup.exe" /S"#
    )]
    #[case(r#"Title = "A \"quoted\" title""#, "Title", r#"A "quoted" title"#)]
    fn parses_config_pair(#[case] line: &str, #[case] key: &str, #[case] value: &str) {
        assert_eq!(parse_pair(line), Some((key.to_owned(), value.to_owned())));
    }

    #[rstest]
    #[case("setup.exe", "setup.exe")]
    #[case(
        r"RECentral_Installer\REC\setup.exe",
        "RECentral_Installer/REC/setup.exe"
    )]
    #[case(r#""%%T\setup.exe" /S"#, "setup.exe")]
    #[case(r".\bin\install.exe -q", "bin/install.exe")]
    fn program_path_from_command(#[case] command: &str, #[case] expected: &str) {
        assert_eq!(program_path(command), expected);
    }
}
