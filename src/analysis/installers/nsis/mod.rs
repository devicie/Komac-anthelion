mod entry;
mod error;
mod file_system;
mod first_header;
mod header;
mod language;
mod registry;
mod section;
mod state;
mod strings;
mod variables;
mod version;

use std::{
    io,
    io::{Read, Seek, SeekFrom},
};

use bzip2::read::BzDecoder;
use camino::{Utf8Path, Utf8PathBuf};
pub use error::NsisError;
use flate2::{Decompress, read::ZlibDecoder};
use msi::Language;
use registry::Registry;
use state::NsisState;
use strsim::levenshtein;
use tracing::{debug, error, warn};
use typed_path::{Utf8Component, Utf8WindowsPath, Utf8WindowsPathBuf};
use variables::Variables;
use winget_types::{
    LanguageTag,
    installer::{
        AppsAndFeaturesEntries, AppsAndFeaturesEntry, Architecture, InstallationMetadata,
        Installer, InstallerType, Scope,
    },
    utils::ValidFileExtensions,
};
use zerocopy::LE;

use super::{
    nsis::{
        entry::{Entry, EntryError},
        file_system::FsEntry,
        first_header::FirstHeader,
        header::{Compression, Decoder, Decompressed, Header, nsis_bzip2},
    },
    pe::{PE, utils::machine_from_exe_reader},
    utils::{LzmaStreamHeader, RELATIVE_PROGRAM_FILES_64, RELATIVE_TEMP_FOLDER},
};
use crate::{
    analysis::Installers,
    read::ReadBytesExt,
    traits::{FromMachine, IntoWingetArchitecture},
};

const APP_32: &str = "app-32";
const APP_64: &str = "app-64";

/// NSIS writes its first header on a 512-byte boundary.
const FIRST_HEADER_ALIGNMENT: u64 = 512;

/// How far past the PE overlay to look for the first header.
///
/// The first header does not always begin exactly at the overlay: a tool that edits an installer's
/// resources can grow a section without fixing up the section table, leaving the section headers
/// describing less data than the file actually holds. NSIS's own exehead copes with this by
/// scanning its file in 512-byte steps for the first header, so scan too, but only far enough to
/// cover a misplaced section rather than reading through every non-NSIS executable in full.
const FIRST_HEADER_SEARCH_LIMIT: u64 = 1 << 20;

/// How far the end of an installer's data may fall short of `data_end` and still be its data.
///
/// An Authenticode signature is aligned to 8 bytes, so a signed installer's data can be followed by
/// up to 7 bytes of padding.
const DATA_END_TOLERANCE: u64 = 8;

/// Finds the NSIS first header at or after the PE overlay offset.
///
/// `data_end` is where the installer's data has to end: the start of the certificate table for a
/// signed installer, and the end of the file otherwise.
fn find_first_header<R: Read + Seek>(
    mut reader: R,
    overlay_offset: u64,
    data_end: u64,
) -> io::Result<Option<(u64, FirstHeader)>> {
    /// Returns `true` if the header describes data that ends where the installer's data ends.
    fn describes_data_to_end(offset: u64, first_header: &FirstHeader, data_end: u64) -> bool {
        let end = offset + u64::from(first_header.length_of_following_data());

        end <= data_end && data_end - end < DATA_END_TOLERANCE
    }

    let start = overlay_offset.next_multiple_of(FIRST_HEADER_ALIGNMENT);

    reader.seek(SeekFrom::Start(start))?;

    let mut offset = start;
    while offset - start <= FIRST_HEADER_SEARCH_LIMIT {
        match FirstHeader::try_read_from_io(&mut reader) {
            // The overlay is where the first header belongs, so take it there without question
            Ok(first_header) if offset == start => return Ok(Some((offset, first_header))),
            // Further in, the signature alone could be a payload rather than this installer's own
            // data, so only take a header that accounts for the rest of the file
            Ok(first_header) if describes_data_to_end(offset, &first_header, data_end) => {
                return Ok(Some((offset, first_header)));
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Ok(_) | Err(_) => {}
        }

        offset += FIRST_HEADER_ALIGNMENT;
        reader.seek(SeekFrom::Start(offset))?;
    }

    Ok(None)
}

pub struct Nsis {
    pub architecture: Architecture,
    pub is_portable: bool,
    pub registry: Registry,
    pub primary_language_id: u16,
    pub install_directory: Option<Utf8WindowsPathBuf>,
}

impl Nsis {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, NsisError> {
        // Get the PE overlay offset
        let overlay_offset = pe.overlay_offset().ok_or(NsisError::NotNsisFile)?;

        let manifest = pe.manifest(&mut reader).ok();

        // The installer's data ends where its signature begins, or at the end of the file
        let data_end = pe.certificate_table().map_or_else(
            || reader.seek(SeekFrom::End(0)).unwrap_or(u64::MAX),
            |certificate_table| u64::from(certificate_table.virtual_address()),
        );

        // Find and read the first header at or after the overlay
        let (first_header_offset, first_header) =
            find_first_header(&mut reader, overlay_offset, data_end)
                .map_err(|_| NsisError::NotNsisFile)?
                .ok_or(NsisError::NotNsisFile)?;

        let data_offset = first_header_offset + size_of::<FirstHeader>() as u64;

        // `Header::decompress` reads from the reader's current position
        reader.seek(SeekFrom::Start(data_offset))?;

        debug!(first_header_offset, ?first_header, data_offset);

        let Decompressed {
            data: decompressed_data,
            is_solid,
            non_solid_start_offset,
            compression,
            decoder,
        } = Header::decompress(&mut reader, &first_header)?;

        let architecture = pe.winget_architecture();

        let header = Header::read_from(&decompressed_data, architecture.is_64_bit())?;

        debug!(?header);

        let mut state = NsisState::new(&decompressed_data, &header, manifest.as_deref())?;

        // Jim Park's Unicode fork of NSIS 2 adds instructions in the middle of the opcode list, so
        // its entries mean something different to the same opcodes in NSIS 2 and 3. Executing them
        // as if they were NSIS 2 entries would invent registry values and install locations, so the
        // installer is identified as NSIS without anything that simulating its code would give.
        if state.is_park() {
            warn!("Not simulating code execution: NSIS Park installers are not supported");
        } else {
            // https://nsis.sourceforge.io/Reference/.onInit
            if header.code_on_init() != -1 {
                debug!("Simulating code execution for .onInit callback");
                if let Err(invalid_entry) = state.execute_code_segment(header.code_on_init()) {
                    error!(%invalid_entry);
                }
            }

            for (index, section) in header.blocks().sections(&decompressed_data).enumerate() {
                debug!(
                    r#"Simulating code execution for section {index} "{}""#,
                    state.get_string(section.name_offset())
                );
                match state.execute_code_segment(section.code_offset()) {
                    Ok(Entry::Quit) => break,
                    Err(invalid_entry) => error!(%invalid_entry),
                    _ => {}
                }
            }

            // https://nsis.sourceforge.io/Reference/.onInstSuccess
            if header.code_on_inst_success() != -1 {
                debug!("Simulating code execution for .onInstSuccess callback");
                match state.execute_code_segment(header.code_on_inst_success()) {
                    Err(EntryError::Abort { .. }) | Ok(..) => {}
                    Err(invalid_entry) => error!(%invalid_entry),
                }
            }
        }

        let mut architecture =
            Option::from(architecture).filter(|&architecture| architecture != Architecture::X86);

        for entry in state.file_system.entries().map(FsEntry::name) {
            // If there is an app-64 entry, the app is x64.
            // If there is an app-32 entry or both entries are present, the app is x86.
            // (x86 apps can still install on x64 systems)
            if entry.contains(APP_64) && architecture.is_none() {
                architecture = Some(Architecture::X64);
            } else if entry.contains(APP_32) {
                architecture = Some(Architecture::X86);
            }
        }

        debug!(%state.registry, %state.file_system);

        architecture = architecture
            .or_else(|| {
                let mut has_32_bit_section = false;
                let mut has_64_bit_section = false;

                for section in header.blocks().sections(&decompressed_data) {
                    let name = state.get_string(section.name_offset());
                    has_32_bit_section |= name.contains("32Bit") || name.contains("32-bit");
                    has_64_bit_section |= name.contains("64Bit") || name.contains("64-bit");
                }

                match (has_32_bit_section, has_64_bit_section) {
                    (true, true) => Some(Architecture::X86),
                    (false, true) => Some(Architecture::X64),
                    _ => None,
                }
            })
            .or_else(|| {
                state
                    .variables
                    .install_dir()
                    .is_some_and(|dir| dir.as_str().contains(RELATIVE_PROGRAM_FILES_64))
                    .then_some(Architecture::X64)
            })
            .or_else(|| {
                let app_name = state.get_string(state.language_table.name_offset()?);
                state
                    .file_system
                    .files()
                    .filter(|file| {
                        ValidFileExtensions::from_path(Utf8Path::new(file.name()))
                            .is_ok_and(|extension| extension == ValidFileExtensions::Exe)
                    })
                    .min_by_key(|file| levenshtein(file.name(), &app_name))
                    .and_then(|file| {
                        let mut position = file.position()?;
                        if !is_solid {
                            position += data_offset
                                + u64::from(non_solid_start_offset)
                                + size_of::<u32>() as u64;
                        }

                        if !is_solid && compression == Compression::BZip2 {
                            let reader = decoder.into_inner();
                            reader
                                .seek(SeekFrom::Start(position - size_of::<u32>() as u64))
                                .ok()?;
                            let compressed_size = reader.read_u32::<LE>().ok()? & !0x8000_0000;
                            let decoder = nsis_bzip2::Decoder::new(
                                reader,
                                Some(compressed_size as usize),
                                1 << 20,
                            )
                            .ok()?;
                            let machine = machine_from_exe_reader(decoder).ok()?;
                            return Some(Architecture::from_machine(machine));
                        }

                        let mut decoder = if is_solid {
                            let decoder = decoder.into_inner();
                            decoder.seek(SeekFrom::Start(position)).ok()?;
                            match compression {
                                Compression::Lzma(filter_flag) => {
                                    decoder
                                        .seek_relative(
                                            i64::try_from(position).ok()? + i64::from(filter_flag),
                                        )
                                        .ok()?;
                                    let header = decoder.read_t::<LzmaStreamHeader>().ok()?;
                                    Decoder::new_lzma1(decoder, header).ok()?
                                }
                                Compression::BZip2 => Decoder::BZip2(BzDecoder::new(decoder)),
                                Compression::Zlib => {
                                    Decoder::Zlib(ZlibDecoder::new_with_decompress(
                                        decoder,
                                        Decompress::new(false),
                                    ))
                                }
                                Compression::None => Decoder::None(decoder),
                            }
                        } else {
                            decoder
                        };

                        if is_solid {
                            // Seek to file
                            io::copy(&mut decoder.by_ref().take(position), &mut io::sink()).ok()?;
                        }

                        let machine = machine_from_exe_reader(decoder).ok()?;
                        Some(Architecture::from_machine(machine))
                    })
            });

        // Without simulating a Park installer's code, the install directory in its header is
        // whatever the compiler left there rather than where the installer actually installs
        let install_directory = (!state.is_park())
            .then(|| {
                state
                    .variables
                    .install_dir()
                    .map(Utf8WindowsPath::to_path_buf)
            })
            .flatten();

        Ok(Self {
            architecture: architecture.unwrap_or(Architecture::X86),
            is_portable: state.is_portable(),
            registry: state.registry,
            install_directory,
            primary_language_id: state.language_table.id(),
        })
    }

    pub fn display_name(&self) -> Option<&registry::Value> {
        const DISPLAY_NAME: &str = "DisplayName";

        self.registry.get_value_by_name(DISPLAY_NAME)
    }
}

impl Installers for Nsis {
    fn installers(&self) -> Vec<Installer> {
        let product_code = self.registry.product_code();
        let detected_scope = self.registry.product_code_scope();
        let install_directory_scope = self
            .install_directory
            .as_deref()
            .and_then(Scope::from_install_directory);
        let scope = match (detected_scope, install_directory_scope) {
            (Some(detected_scope), Some(install_directory_scope))
                if detected_scope != install_directory_scope =>
            {
                None
            }
            (detected_scope, install_directory_scope) => detected_scope.or(install_directory_scope),
        };
        let display_name = self.display_name();
        let publisher = self.registry.get_value_by_name("Publisher");
        let display_version = self.registry.get_value_by_name("DisplayVersion");

        let installer = Installer {
            locale: Language::from_code(self.primary_language_id)
                .tag()
                .parse::<LanguageTag>()
                .ok(),
            architecture: self.architecture,
            r#type: if self.is_portable {
                Some(InstallerType::Portable)
            } else {
                Some(InstallerType::Nullsoft)
            },
            scope,
            product_code: product_code.map(str::to_owned),
            apps_and_features_entries: if display_name.is_some()
                || publisher.is_some()
                || display_version.is_some()
            {
                AppsAndFeaturesEntry::builder()
                    .maybe_display_name(display_name.cloned())
                    .maybe_publisher(publisher.cloned())
                    .maybe_display_version(display_version.cloned())
                    .maybe_product_code(product_code)
                    .build()
                    .into()
            } else {
                AppsAndFeaturesEntries::new()
            },
            installation_metadata: InstallationMetadata::new_install_location(
                self.install_directory
                    .as_deref()
                    .filter(|path| {
                        !path.components().next().is_none_or(|component| {
                            component
                                .as_str()
                                .eq_ignore_ascii_case(RELATIVE_TEMP_FOLDER)
                        })
                    })
                    .map(|path| Utf8PathBuf::from(path.as_str())),
            ),
            ..Installer::default()
        };

        vec![installer]
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use registry::RegRoot;

    use super::*;

    const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Test.App";

    const OVERLAY_OFFSET: u64 = 2 * FIRST_HEADER_ALIGNMENT;

    const SIGNATURE: &[u8; 16] = b"\xEF\xBE\xAD\xDENullsoftInst";

    /// Builds a file whose first header is `header_offset` bytes in and claims `length_of_data`
    /// bytes of following data.
    fn file_with_first_header(header_offset: u64, length_of_data: u32, len: usize) -> Vec<u8> {
        let mut data = vec![0; len];
        let offset = header_offset as usize;

        data[offset..offset + 0x04].copy_from_slice(&0u32.to_le_bytes()); // flags
        data[offset + 0x04..offset + 0x14].copy_from_slice(SIGNATURE);
        data[offset + 0x14..offset + 0x18].copy_from_slice(&1u32.to_le_bytes()); // header length
        data[offset + 0x18..offset + 0x1C].copy_from_slice(&length_of_data.to_le_bytes());

        data
    }

    #[test]
    fn finds_first_header_at_the_overlay() {
        const LENGTH_OF_DATA: u32 = 64;

        let data = file_with_first_header(OVERLAY_OFFSET, LENGTH_OF_DATA, 4096);
        let data_end = data.len() as u64;

        let (offset, first_header) = find_first_header(Cursor::new(data), OVERLAY_OFFSET, data_end)
            .unwrap()
            .unwrap();

        assert_eq!(offset, OVERLAY_OFFSET);
        assert_eq!(first_header.length_of_following_data(), LENGTH_OF_DATA);
    }

    #[test]
    fn finds_first_header_past_the_overlay() {
        // A section that a resource editor moved without fixing up the section table leaves the
        // overlay offset short of the data
        const HEADER_OFFSET: u64 = OVERLAY_OFFSET + 4096;
        const LEN: usize = 8192;

        let data = file_with_first_header(HEADER_OFFSET, (LEN as u64 - HEADER_OFFSET) as u32, LEN);

        let (offset, _) = find_first_header(Cursor::new(data), OVERLAY_OFFSET, LEN as u64)
            .unwrap()
            .unwrap();

        assert_eq!(offset, HEADER_OFFSET);
    }

    #[test]
    fn ignores_first_header_past_the_overlay_that_is_not_the_installer_data() {
        // An NSIS installer carried as a payload has a first header of its own that does not
        // account for the rest of the file
        const HEADER_OFFSET: u64 = OVERLAY_OFFSET + 4096;
        const LEN: usize = 8192;

        let data = file_with_first_header(HEADER_OFFSET, 64, LEN);

        assert!(
            find_first_header(Cursor::new(data), OVERLAY_OFFSET, LEN as u64)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn does_not_find_a_first_header_without_a_signature() {
        let data = vec![0; 8192];
        let len = data.len() as u64;

        assert!(
            find_first_header(Cursor::new(data), OVERLAY_OFFSET, len)
                .unwrap()
                .is_none()
        );
    }

    fn nsis_with_scope_signals(root: RegRoot, install_directory: &str) -> Nsis {
        let mut registry = Registry::new();
        registry.insert_value(root, UNINSTALL_KEY, "DisplayName", "Test App");

        Nsis {
            architecture: Architecture::X64,
            is_portable: false,
            registry,
            primary_language_id: 1033,
            install_directory: Some(Utf8WindowsPathBuf::from(install_directory)),
        }
    }

    #[test]
    fn keeps_nsis_scope_when_detected_scope_matches_install_location_scope() {
        let installer =
            nsis_with_scope_signals(RegRoot::HKEY_LOCAL_MACHINE, r"%ProgramFiles%\Test App")
                .installers()
                .remove(0);

        assert_eq!(installer.scope, Some(Scope::Machine));
    }

    #[test]
    fn does_not_set_nsis_scope_when_detected_scope_conflicts_with_install_location_scope() {
        let installer =
            nsis_with_scope_signals(RegRoot::HKEY_CURRENT_USER, r"%ProgramFiles%\Test App")
                .installers()
                .remove(0);

        assert_eq!(installer.scope, None);
    }
}
