use std::io::{self, Cursor, Read, Seek, SeekFrom};

use memchr::memmem;
use sevenz_rust2::{ArchiveReader, Password};
use thiserror::Error;
use tracing::debug;
use winget_types::installer::{Installer, InstallerType, Switches};

use super::{
    msi::Msi,
    pe::{PE, resource::SectionReader},
};
use crate::analysis::Installers;

/// The InstallAware runtime library that is packed alongside every InstallAware setup.
const MIA_LIB: &str = "mia.lib";

const SEVEN_Z_SIGNATURE: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

/// The maximum number of bytes into the overlay to search for the 7z archive, allowing for the
/// 7z SFX config (`;!@Install@!UTF-8! ... ;!@InstallEnd@!`) that precedes it.
const MAX_ARCHIVE_SEARCH: u64 = 1 << 12;

#[derive(Error, Debug)]
pub enum InstallAwareError {
    #[error("File is not an InstallAware installer")]
    NotInstallAwareFile,
    #[error(transparent)]
    SevenZ(#[from] sevenz_rust2::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct InstallAware {
    installers: Vec<Msi>,
}

impl InstallAware {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, InstallAwareError> {
        let overlay_offset = pe
            .overlay_offset()
            .ok_or(InstallAwareError::NotInstallAwareFile)?;

        reader.seek(SeekFrom::Start(overlay_offset))?;
        let mut header = Vec::new();
        reader
            .by_ref()
            .take(MAX_ARCHIVE_SEARCH)
            .read_to_end(&mut header)?;

        let archive_offset = memmem::find(&header, &SEVEN_Z_SIGNATURE)
            .ok_or(InstallAwareError::NotInstallAwareFile)?;

        let mut archive = ArchiveReader::new(
            SectionReader::from_offset(&mut reader, overlay_offset + archive_offset as u64)?,
            Password::empty(),
        )
        .map_err(|_| InstallAwareError::NotInstallAwareFile)?;

        let file_names = archive
            .archive()
            .files
            .iter()
            .filter(|entry| !entry.is_directory())
            .map(|entry| entry.name().to_owned())
            .collect::<Vec<_>>();

        if !file_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(MIA_LIB))
        {
            return Err(InstallAwareError::NotInstallAwareFile);
        }

        // The setup's MSI is at the root of the archive, while the `data` directory holds a copy
        let mut installers = Vec::new();
        for name in file_names.iter().filter(|name| {
            !name.contains('/')
                && name
                    .rsplit_once('.')
                    .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("msi"))
        }) {
            debug!(msi = %name);
            installers.push(Msi::new(Cursor::new(archive.read_file(name)?))?);
        }

        if installers.is_empty() {
            return Err(InstallAwareError::NotInstallAwareFile);
        }

        Ok(Self { installers })
    }
}

impl Installers for InstallAware {
    fn installers(&self) -> Vec<Installer> {
        // https://www.installaware.com/mh52/desktop/setupcommandlineparameters.htm
        let switches = Switches::builder()
            .silent("/s".parse().unwrap())
            .silent_with_progress("/s".parse().unwrap())
            .install_location(r#"TARGETDIR="<INSTALLPATH>""#.parse().unwrap())
            .log(r#"/l="<LOGPATH>""#.parse().unwrap())
            .build();

        self.installers
            .iter()
            .map(|msi| {
                let mut installer = msi.installers().into_iter().next().unwrap_or_default();
                installer.r#type = Some(InstallerType::Exe);
                installer.switches = switches.clone();
                installer
            })
            .collect()
    }
}
