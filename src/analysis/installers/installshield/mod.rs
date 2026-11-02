mod file;
mod return_codes;
mod setup_ini;
mod setup_iss;
mod setup_xml;

use std::{
    ffi::CStr,
    io::{self, Read, Seek, SeekFrom},
};

use encoding_rs::UTF_16LE;
pub use file::FileError;
use file::decode_text;
use msi::Language;
use thiserror::Error;
use tracing::{debug, warn};
use winget_types::{
    LanguageTag,
    installer::{
        AppsAndFeaturesEntry, Architecture, InstallModes, InstallationMetadata, Installer,
        InstallerType, Scope, Switches,
    },
};
use zerocopy::LittleEndian;

use crate::{
    analysis::{
        Installers, SiblingFiles,
        installers::{
            installshield::{
                file::File, setup_ini::SetupIni, setup_iss::SetupIss, setup_xml::SetupXml,
            },
            pe::{PE, VSVersionInfo},
            utils::{RELATIVE_PROGRAM_FILES_64, install_directory_scope},
        },
    },
    read::ReadBytesExt,
    traits::FromMachine,
};

#[derive(Error, Debug)]
pub enum InstallShieldError {
    #[error("File is not an InstallShield installer")]
    NotInstallShieldFile,
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Ini(#[from] serini::Error),
}

#[derive(Debug)]
pub struct InstallShield {
    pub architecture: Architecture,
    pub setup_ini: Option<SetupIni>,
    pub setup_iss: Option<SetupIss>,
    pub setup_xml: Option<SetupXml>,
}

impl InstallShield {
    /// Analyses an InstallShield installer, falling back to the `setup.ini` and `setup.iss` from
    /// beside it for those that aren't embedded, as a setup launcher reads them from its folder.
    pub fn new<R: Read + Seek>(
        mut reader: R,
        pe: &PE,
        siblings: &SiblingFiles,
    ) -> Result<Self, InstallShieldError> {
        let Some(overlay_start) = pe.overlay_offset() else {
            return Err(InstallShieldError::NotInstallShieldFile);
        };

        let file_end = reader.seek(SeekFrom::End(0))?;
        let overlay_data_end = overlay_data_end(
            overlay_start,
            pe.certificate_table()
                .map(|directory| u64::from(directory.virtual_address())),
            file_end,
        );

        enum InstallScriptEncoding {
            Unicode,
            Ascii,
        }

        // This reads from the resource section, so it has to happen before seeking to the overlay
        let encoding =
            pe.vs_version_info(&mut reader)
                .ok()
                .and_then(|bytes| {
                    VSVersionInfo::read_from(&bytes).ok().map(|version_info| {
                        let string_table = version_info.string_table();
                        if string_table
                            .get("ISInternalDescription")
                            .is_some_and(|description| description.starts_with("InstallScript"))
                        {
                            Some(InstallScriptEncoding::Unicode)
                        } else if string_table.get("ProductName").is_some_and(|name| {
                            matches!(*name, "InstallShield (R)" | "InstallShield")
                        }) {
                            Some(InstallScriptEncoding::Ascii)
                        } else {
                            None
                        }
                    })
                })
                .flatten();

        // The version info alone identifies a setup launcher, which needn't embed any files: one
        // whose overlay is empty or nothing but its Authenticode signature reads setup.ini and
        // data1.cab from beside itself instead
        let is_setup_launcher = encoding.is_some();
        let has_overlay_data = overlay_data_end > overlay_start;
        if !has_overlay_data && !is_setup_launcher {
            return Err(InstallShieldError::NotInstallShieldFile);
        }

        reader
            .seek(SeekFrom::Start(overlay_start))
            .map_err(|_| InstallShieldError::NotInstallShieldFile)?;

        // Running out of bytes while reading the file table means the overlay isn't one, so treat
        // it the same as a wrong magic rather than failing the whole exe's analysis
        let files = match encoding {
            _ if !has_overlay_data => Ok(Vec::new()),
            Some(InstallScriptEncoding::Unicode) => {
                let file_count = reader.read_u32::<LittleEndian>().map_err(on_eof)?;
                parse_installscript_entries(
                    &mut reader,
                    file_count,
                    read_utf16le_strz,
                    overlay_data_end,
                )
            }
            Some(InstallScriptEncoding::Ascii) => parse_installscript_entries(
                &mut reader,
                u32::MAX,
                read_ascii_strz,
                overlay_data_end,
            ),
            None => {
                let header = Header::read(&mut reader)?;
                debug!(?header);
                match header.kind {
                    Kind::Plain => parse_plain_entries(&mut reader, header.num_files),
                    Kind::SetupStream => {
                        parse_stream_entries(&mut reader, header.num_files, header.header_type)
                    }
                }
            }
        }
        .map_err(|error| match error {
            InstallShieldError::Io(error) => on_eof(error),
            error => error,
        });
        let files = match files {
            Ok(files) => files,
            Err(InstallShieldError::NotInstallShieldFile) if is_setup_launcher => Vec::new(),
            Err(error) => return Err(error),
        };

        debug!(files = ?files.iter().map(|file| file.name.as_str()).collect::<Vec<_>>());

        let parse_setup_ini = |content: &str| SetupIni::from_str(content).ok();
        let setup_ini = find_and_parse(&files, &mut reader, "setup.ini", parse_setup_ini)
            .or_else(|| parse_sibling(siblings, "setup.ini", parse_setup_ini));

        let parse_setup_iss = |content: &str| serini::from_str::<SetupIss>(content).ok();
        let setup_iss = find_and_parse(&files, &mut reader, "setup.iss", parse_setup_iss)
            .or_else(|| parse_sibling(siblings, "setup.iss", parse_setup_iss));

        let setup_xml = find_and_parse(&files, &mut reader, "Setup.xml", |content| {
            quick_xml::de::from_str::<SetupXml>(content).ok()
        });

        if setup_ini.is_none() && setup_iss.is_none() && setup_xml.is_none() && !is_setup_launcher {
            return Err(InstallShieldError::NotInstallShieldFile);
        }

        Ok(Self {
            architecture: Architecture::from_machine(pe.machine()),
            setup_ini,
            setup_iss,
            setup_xml,
        })
    }
}

fn find_and_parse<R: Read + Seek, T>(
    files: &[File],
    reader: &mut R,
    name: &str,
    parse: fn(&str) -> Option<T>,
) -> Option<T> {
    files
        .iter()
        .rev()
        .find(|f| f.name.eq_ignore_ascii_case(name))
        .and_then(|f| match f.read_text(reader) {
            Ok(Some(content)) => {
                debug!("{content}");
                let result = parse(&content);
                if result.is_none() {
                    debug!("Failed to parse {}", f.name);
                }
                result
            }
            Ok(None) => None,
            Err(e) => {
                debug!("Failed to read {}: {e}", f.name);
                None
            }
        })
}

fn parse_sibling<T>(
    siblings: &SiblingFiles,
    name: &str,
    parse: fn(&str) -> Option<T>,
) -> Option<T> {
    let content = decode_text(siblings.get(name)?);
    debug!("{name} from beside the setup launcher: {content}");
    let result = parse(&content);
    if result.is_none() {
        debug!("Failed to parse {name} from beside the setup launcher");
    }
    result
}

impl Installers for InstallShield {
    fn installers(&self) -> Vec<Installer> {
        let startup = self.setup_ini.as_ref().map(|ini| &ini.startup);
        let xml = self.setup_xml.as_ref();
        let iss = self.setup_iss.as_ref();
        let script_driven = startup.and_then(|s| s.script_driven.as_deref());
        let msi_based = matches!(script_driven, Some("0" | "2"));

        if self.setup_ini.is_none() && iss.is_none() && xml.is_none() {
            warn!(
                "InstallShield setup launcher without its setup.ini - its product code and \
                 installer switches may need checking"
            );
        }

        if script_driven == Some("4") && iss.is_none() {
            warn!(
                "InstallScriptUnicode installer without embedded setup.iss - \
                 a separate response file may be required for silent installation: \
                 https://github.com/microsoft/winget-pkgs/issues/246"
            );
        }

        let publisher = startup
            .and_then(|s| s.company_name.as_deref())
            .or_else(|| iss.map(|iss| iss.application.company.as_str()))
            .or_else(|| {
                xml.and_then(|xml| {
                    xml.languages
                        .language
                        .iter()
                        .find(|lang| lang.lcid == xml.language_selection.default)
                        .and_then(|lang| {
                            lang.strings
                                .get(&xml.arp_info.publisher)
                                .map(|s| s.as_str())
                        })
                        .or(Some(xml.arp_info.publisher.as_str()))
                })
            });

        let product_code = startup
            .and_then(|s| s.product_code.as_ref())
            .map(|code| {
                if msi_based {
                    code.clone()
                } else if script_driven == Some("4") {
                    format!("{{{code}}}")
                } else {
                    format!("InstallShield_{code}")
                }
            })
            .or_else(|| {
                xml.and_then(|xml| {
                    xml.get_property("ProductCode")
                        .or_else(|| Some(xml.suite_id.clone()))
                })
            });

        let version = startup
            .and_then(|s| s.product_version.as_deref())
            .or_else(|| iss.map(|iss| iss.application.version.as_str()))
            .or_else(|| xml.map(|xml| xml.arp_info.version.as_str()));

        let locale = self
            .setup_ini
            .as_ref()
            .and_then(|ini| ini.languages.as_ref())
            .and_then(|languages| {
                u16::from_str_radix(languages.default.trim_start_matches("0x"), 16).ok()
            })
            .or_else(|| xml.and_then(|xml| xml.language_selection.default.parse().ok()))
            .and_then(|id| Language::from_code(id).tag().parse::<LanguageTag>().ok());

        let display_name = startup
            .and_then(|s| s.product.clone())
            .or_else(|| iss.map(|iss| iss.application.name.clone()))
            .or_else(|| xml.map(|xml| xml.arp_info.display_name.clone()))
            .or_else(|| xml.and_then(|xml| xml.get_property("ProductName")));

        let upgrade_code = startup
            .and_then(|s| s.upgrade_code.clone())
            .or_else(|| xml.and_then(|xml| xml.get_property("UpgradeCode")));

        // TODO are these MSI vars? could reuse logic from burn/manifest/variable.rs
        let install_dir = xml
            .and_then(|xml| xml.get_property("INSTALLDIR"))
            .map(|value| value.replace("[ProgramFiles64Folder]", RELATIVE_PROGRAM_FILES_64));

        let scope = install_dir
            .as_deref()
            .and_then(install_directory_scope)
            .or(Some(Scope::Machine));

        vec![Installer {
            locale,
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            scope,
            product_code: product_code.clone(),
            apps_and_features_entries: AppsAndFeaturesEntry::builder()
                .maybe_display_name(display_name)
                .maybe_publisher(publisher)
                .maybe_display_version(version)
                .maybe_product_code(product_code)
                .maybe_upgrade_code(upgrade_code)
                .build()
                .into(),
            installation_metadata: InstallationMetadata::new_install_location(
                install_dir.map(winget_types::PathBuf::from),
            ),
            install_modes: InstallModes::all(),
            switches: if xml.is_some() {
                Switches::builder()
                    .silent("/silent".parse().unwrap())
                    .silent_with_progress("/passive".parse().unwrap())
                    .log("/log \"<LOGPATH>\"".parse().unwrap())
                    .repair("/repair".parse().unwrap())
                    .custom("/clone_wait".parse().unwrap())
                    .build()
            } else if msi_based {
                Switches::builder()
                    .silent("/s /v\"/qn /norestart\"".parse().unwrap())
                    .silent_with_progress("/s /v\"/qb /norestart\"".parse().unwrap())
                    .install_location("/v\"INSTALLDIR=\"\"<INSTALLPATH>\"\"\"".parse().unwrap())
                    .log("/v\"/log \"\"<LOGPATH>\"\"\"".parse().unwrap())
                    .custom("/clone_wait".parse().unwrap())
                    .build()
            } else {
                Switches::builder()
                    .silent("/s".parse().unwrap())
                    .silent_with_progress("/s".parse().unwrap())
                    .custom("/clone_wait".parse().unwrap())
                    .build()
            },
            expected_return_codes: return_codes::expected_return_codes(msi_based),
            ..Installer::default()
        }]
    }
}

/// Returns where the overlay's data ends, which is where the Authenticode signature starts if
/// it's in the overlay, including when the signature is the whole overlay.
fn overlay_data_end(overlay_start: u64, certificate_offset: Option<u64>, file_end: u64) -> u64 {
    certificate_offset
        .filter(|&offset| offset >= overlay_start)
        .unwrap_or(file_end)
}

/// Maps running out of bytes to [`InstallShieldError::NotInstallShieldFile`], as data that ends
/// before its structure does can't be an InstallShield installer
fn on_eof(error: io::Error) -> InstallShieldError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        InstallShieldError::NotInstallShieldFile
    } else {
        InstallShieldError::Io(error)
    }
}

fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

#[derive(Debug)]
struct Header {
    kind: Kind,
    num_files: u16,
    header_type: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    SetupStream,
}

impl Header {
    fn read<R: Read + Seek>(reader: &mut R) -> Result<Self, InstallShieldError> {
        // An overlay too short to hold a header can't be an InstallShield installer, so run out of
        // bytes the same way a wrong magic does rather than failing the whole exe's analysis
        // Skip optional PDB 2.0 info (NB10 signature)
        let mut sig = [0u8; 4];
        reader.read_exact(&mut sig).map_err(on_eof)?;
        if &sig == b"NB10" {
            reader.seek(SeekFrom::Current(12))?;
            while read_u8(reader).map_err(on_eof)? != 0 {}
        } else {
            reader.seek(SeekFrom::Current(-4))?;
        }

        let mut magic = [0u8; 14];
        reader.read_exact(&mut magic).map_err(on_eof)?;
        let num_files = reader.read_u16::<LittleEndian>().map_err(on_eof)?;
        let header_type = reader.read_u32::<LittleEndian>().map_err(on_eof)?;
        reader.seek(SeekFrom::Current(26))?; // reserved
        let kind = match CStr::from_bytes_until_nul(&magic)
            .ok()
            .and_then(|c| c.to_str().ok())
        {
            Some("InstallShield") => Kind::Plain,
            Some("ISSetupStream") => Kind::SetupStream,
            _ => return Err(InstallShieldError::NotInstallShieldFile),
        };

        Ok(Self {
            kind,
            num_files,
            header_type,
        })
    }
}

fn parse_plain_entries<R: Read + Seek>(
    reader: &mut R,
    count: u16,
) -> Result<Vec<File>, InstallShieldError> {
    let mut files = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut raw_name = [0u8; 260]; // MAX_PATH
        reader.read_exact(&mut raw_name)?;
        let encoded_flags = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(4))?; // reserved
        let size = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(40))?; // 8 + 2 + 30 reserved

        let name = CStr::from_bytes_until_nul(&raw_name)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_default();
        let offset = reader.stream_position()?;
        reader.seek(SeekFrom::Current(i64::from(size)))?;

        files.push(File {
            name,
            encoded_flags,
            size,
            offset,
        });
    }
    Ok(files)
}

fn parse_stream_entries<R: Read + Seek>(
    reader: &mut R,
    count: u16,
    header_type: u32,
) -> Result<Vec<File>, InstallShieldError> {
    let mut files = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let filename_len = reader.read_u32::<LittleEndian>()?;
        let encoded_flags = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(2))?; // reserved
        let size = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(10))?; // 8 + 2 reserved
        if header_type == 4 {
            reader.seek(SeekFrom::Current(24))?; // attributes
        }

        let name = if filename_len == 0 {
            String::new()
        } else {
            let mut buffer = vec![0u8; filename_len as usize];
            reader.read_exact(&mut buffer)?;
            UTF_16LE.decode(&buffer).0.trim_matches('\0').to_owned()
        };
        let offset = reader.stream_position()?;
        reader.seek(SeekFrom::Current(i64::from(size)))?;

        files.push(File {
            name,
            encoded_flags,
            size,
            offset,
        });
    }

    Ok(files)
}

fn parse_installscript_entries<R: Read + Seek>(
    reader: &mut R,
    count: u32,
    read: fn(&mut R) -> Result<String, std::io::Error>,
    end: u64,
) -> Result<Vec<File>, InstallShieldError> {
    let mut files = Vec::new();
    while files.len() < count as usize && reader.stream_position()? < end {
        let name = read(reader)?;
        if name.is_empty() || reader.stream_position()? > end {
            break;
        }
        read(reader)?; // path
        read(reader)?; // version
        let size: u32 = read(reader)?.parse().unwrap_or(0);
        let offset = reader.stream_position()?;
        reader.seek(SeekFrom::Current(i64::from(size)))?;
        files.push(File {
            name,
            encoded_flags: 0,
            size,
            offset,
        });
    }
    Ok(files)
}

fn read_ascii_strz<R: Read>(reader: &mut R) -> Result<String, std::io::Error> {
    let mut buf = Vec::new();
    loop {
        let byte = read_u8(reader)?;
        if byte == 0 {
            break;
        }
        buf.push(byte);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn read_utf16le_strz<R: Read>(reader: &mut R) -> Result<String, std::io::Error> {
    let mut buf = Vec::new();
    loop {
        let code_unit = reader.read_u16::<LittleEndian>()?;
        if code_unit == 0 {
            break;
        }
        buf.extend_from_slice(&code_unit.to_le_bytes());
    }
    Ok(UTF_16LE.decode(&buf).0.into_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rstest::rstest;
    use winget_types::installer::Architecture;

    use super::{
        InstallShield, overlay_data_end, setup_ini,
        setup_ini::{SetupIni, Startup},
        setup_xml,
        setup_xml::{ArpInfo, LanguageSelection, SetupXml},
    };
    use crate::analysis::Installers;

    fn setup_ini(script_driven: &str) -> SetupIni {
        SetupIni {
            startup: Startup {
                cmd_line: None,
                script_driven: Some(script_driven.to_owned()),
                company_name: None,
                package_name: None,
                product: None,
                product_code: None,
                product_version: None,
                upgrade_code: None,
            },
            languages: Some(setup_ini::Languages {
                default: "0x0409".to_owned(),
            }),
        }
    }

    fn setup_xml() -> SetupXml {
        SetupXml {
            suite_id: String::new(),
            arp_info: ArpInfo {
                version: String::new(),
                publisher: String::new(),
                display_name: String::new(),
            },
            language_selection: LanguageSelection {
                default: "1033".to_owned(),
            },
            languages: setup_xml::Languages {
                language: vec![setup_xml::Language {
                    lcid: "1033".to_owned(),
                    strings: HashMap::new(),
                }],
            },
            set_property: Vec::new(),
        }
    }

    #[rstest]
    #[case::basic_msi(Some(setup_ini("0")), None)]
    #[case::installscript(Some(setup_ini("1")), None)]
    #[case::installscript_msi(Some(setup_ini("2")), None)]
    #[case::suite(None, Some(setup_xml()))]
    fn setup_launcher_waits_for_clone(
        #[case] setup_ini: Option<SetupIni>,
        #[case] setup_xml: Option<SetupXml>,
    ) {
        let installshield = InstallShield {
            architecture: Architecture::X86,
            setup_ini,
            setup_iss: None,
            setup_xml,
        };

        let installers = installshield.installers();
        let custom = installers[0].switches.custom().unwrap();

        assert_eq!(custom.to_string(), "/clone_wait");
    }

    #[rstest]
    #[case::unsigned(0x400, None, 0x800, 0x800)]
    #[case::signature_after_data(0x400, Some(0x600), 0x800, 0x600)]
    #[case::signature_is_whole_overlay(0x400, Some(0x400), 0x800, 0x400)]
    #[case::signature_before_overlay(0x400, Some(0x200), 0x800, 0x800)]
    fn overlay_data_ends_at_signature(
        #[case] overlay_start: u64,
        #[case] certificate_offset: Option<u64>,
        #[case] file_end: u64,
        #[case] expected: u64,
    ) {
        assert_eq!(
            overlay_data_end(overlay_start, certificate_offset, file_end),
            expected
        );
    }

    #[test]
    fn setup_launcher_without_embedded_files() {
        let installshield = InstallShield {
            architecture: Architecture::X86,
            setup_ini: None,
            setup_iss: None,
            setup_xml: None,
        };

        let installers = installshield.installers();
        let installer = &installers[0];

        assert_eq!(installer.switches.silent().unwrap().to_string(), "/s");
        assert_eq!(
            installer.switches.custom().unwrap().to_string(),
            "/clone_wait"
        );
        assert!(installer.product_code.is_none());
    }
}
