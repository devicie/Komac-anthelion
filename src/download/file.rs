use std::{
    fs::File,
    io,
    io::{Read, Seek, SeekFrom},
};

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

/// Gives `file_name` an extension inferred from `file`'s magic bytes when it does not
/// already end in one that analysis can dispatch on.
///
/// Analysis picks its parser purely from the file extension, so a download whose URL
/// carries no usable extension fails outright — ImmyBot's installer redirects to
/// `cdn.immy.bot/immyagent-versions/0.84.1-build.56537`, whose last path segment made
/// komac report `Invalid file extension: 56537` for what is really an MSI.
///
/// Only the two unambiguous signatures are inferred. A zip container is deliberately
/// left alone: `.zip`, `.msix` and `.appx` share it, and guessing produces a wrong
/// manifest silently, which is worse than the loud failure.
pub fn infer_extension(file_name: String, file: &File) -> io::Result<String> {
    const OLE_COMPOUND_FILE: &[u8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
    const PORTABLE_EXECUTABLE: &[u8] = b"MZ";

    if ValidFileExtensions::from_path(Utf8Path::new(&file_name)).is_ok() {
        return Ok(file_name);
    }

    let mut magic = [0; OLE_COMPOUND_FILE.len()];
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let read = reader.read(&mut magic)?;
    let magic = &magic[..read];

    let extension = if magic.starts_with(OLE_COMPOUND_FILE) {
        ValidFileExtensions::Msi
    } else if magic.starts_with(PORTABLE_EXECUTABLE) {
        ValidFileExtensions::Exe
    } else {
        return Ok(file_name);
    };

    Ok(format!("{file_name}.{extension}"))
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
    use std::io::Write;

    use rstest::rstest;
    use tempfile::tempfile;
    use winget_types::{Sha256String, installer::Architecture};

    use super::{DownloadedFile, infer_extension};
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

    #[rstest]
    // ImmyBot's installer: no extension in the URL, MSI on the wire.
    #[case::msi_without_extension(
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1rest",
        "0.84.1-build.56537",
        "0.84.1-build.56537.msi"
    )]
    #[case::exe_without_extension(b"MZ\x90\x00", "installer-latest", "installer-latest.exe")]
    // A valid extension is always left as it is, whatever the bytes say.
    #[case::keeps_existing_extension(b"MZ\x90\x00", "setup.msi", "setup.msi")]
    // Zip containers are ambiguous between .zip, .msix and .appx, so they are not guessed.
    #[case::leaves_zip_alone(b"PK\x03\x04", "bundle-latest", "bundle-latest")]
    #[case::leaves_unknown_alone(b"not an installer", "mystery", "mystery")]
    fn infers_extension_from_magic_bytes(
        #[case] bytes: &[u8],
        #[case] file_name: &str,
        #[case] expected: &str,
    ) {
        let mut file = tempfile().unwrap();
        file.write_all(bytes).unwrap();

        assert_eq!(
            infer_extension(file_name.to_owned(), &file).unwrap(),
            expected
        );
    }

    #[test]
    fn infers_extension_from_an_empty_file() {
        let file = tempfile().unwrap();

        assert_eq!(
            infer_extension("mystery".to_owned(), &file).unwrap(),
            "mystery"
        );
    }
}
