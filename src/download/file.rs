use std::{
    fs::File,
    io::{self, Read},
};

use camino::Utf8Path;
use jiff::civil::Date;
use sha2::{Digest, Sha256, digest::Output};
use winget_types::{Sha256String, installer::Architecture};

use crate::{download::Download, manifests::Url};

pub struct DownloadedFile {
    pub file: File,
    pub download: Download,
    pub sha_256: Sha256String,
    pub last_modified: Option<Date>,
}

impl DownloadedFile {
    /// Creates a [`DownloadedFile`] from a file that is already on disk, associating it with the
    /// URL that it would otherwise have been downloaded from.
    pub fn from_local(path: &Utf8Path, url: Url) -> io::Result<Self> {
        let file = File::open(path)?;
        let sha_256 = Sha256String::from_digest(&sha256_digest(&file)?);
        let file_name = path.file_name().unwrap_or_else(|| path.as_str()).to_owned();
        Ok(Self {
            file,
            download: Download::from_local(url, file_name),
            sha_256,
            last_modified: None,
        })
    }

    pub fn architecture(&self) -> Option<Architecture> {
        self.download.architecture()
    }
}

pub fn sha256_digest<R: Read>(mut reader: R) -> io::Result<Output<Sha256>> {
    let mut digest = Sha256::new();
    let mut buffer = [0; 1 << 13];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }

    Ok(digest.finalize())
}
