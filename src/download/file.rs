use std::{fs::File, io, io::Read};

use camino::Utf8Path;
use chrono::NaiveDate;
use sha2::{Digest, Sha256, digest::Output};
use winget_types::{Sha256String, installer::Architecture, utils::ValidFileExtensions};

use crate::manifests::Url;

pub struct DownloadedFile {
    pub file: File,
    pub url: Url,
    pub sha_256: Sha256String,
    pub file_name: String,
    pub last_modified: Option<NaiveDate>,
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
            url,
            sha_256,
            file_name,
            last_modified: None,
        })
    }

    pub fn architecture(&self) -> Option<Architecture> {
        self.url.override_architecture().or_else(|| {
            if matches!(
                self.file_name.parse(),
                Ok(ValidFileExtensions::MsixBundle | ValidFileExtensions::AppxBundle)
            ) {
                None
            } else {
                Architecture::from_url(self.url.as_str())
            }
        })
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

#[cfg(test)]
mod tests {
    use tempfile::tempfile;
    use winget_types::{Sha256String, installer::Architecture};

    use super::DownloadedFile;
    use crate::manifests::Url;

    fn downloaded_file(url: &str, file_name: &str) -> DownloadedFile {
        DownloadedFile {
            file: tempfile().unwrap(),
            url: url.parse::<Url>().unwrap(),
            sha_256: Sha256String::default(),
            file_name: file_name.to_owned(),
            last_modified: None,
        }
    }

    #[test]
    fn does_not_infer_architecture_for_bundle_with_extensionless_url() {
        let file = downloaded_file(
            "https://example.com/download/WinDirStat_x86_x64_arm64",
            "WinDirStat_x86_x64_arm64.msixbundle",
        );

        assert_eq!(
            Architecture::from_url(file.url.as_str()),
            Some(Architecture::Arm64)
        );
        assert_eq!(file.architecture(), None);
    }

    #[test]
    fn allows_explicit_architecture_override_for_bundle() {
        let file = downloaded_file(
            "https://example.com/download/application|arm64",
            "application.msixbundle",
        );

        assert_eq!(file.architecture(), Some(Architecture::Arm64));
    }

    #[test]
    fn infers_architecture_for_non_bundle() {
        let file = downloaded_file(
            "https://example.com/download/application-arm64",
            "application.exe",
        );

        assert_eq!(file.architecture(), Some(Architecture::Arm64));
    }
}
