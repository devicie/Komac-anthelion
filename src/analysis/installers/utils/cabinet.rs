use std::io::{Cursor, Read, Seek};

use cab::Cabinet;
use camino::Utf8Path;
use tracing::debug;
use winget_types::utils::ValidFileExtensions;

use super::super::Msi;

/// The maximum size of an MSI that is read from a cabinet into memory.
const MAX_MSI_SIZE: u32 = 1 << 30;

/// Returns the names of the files in a cabinet.
pub fn file_names<R: Read + Seek>(cabinet: &Cabinet<R>) -> Vec<String> {
    cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries())
        .map(|file| file.name().to_owned())
        .collect()
}

/// Returns the file name without the leading `.\` components that some cabinets have.
pub fn trim_current_dir(mut name: &str) -> &str {
    while let Some(rest) = name.strip_prefix(".\\").or_else(|| name.strip_prefix("./")) {
        name = rest;
    }
    name
}

/// Returns `true` if the file name has an `.msi` extension.
pub fn is_msi(name: &str) -> bool {
    ValidFileExtensions::from_path(Utf8Path::new(name))
        .is_ok_and(|extension| extension == ValidFileExtensions::Msi)
}

/// Reads and analyses an MSI from a cabinet.
pub fn read_msi<R: Read + Seek>(cabinet: &mut Cabinet<R>, name: &str) -> Option<Msi> {
    let size = cabinet.get_file_entry(name)?.uncompressed_size();
    if size > MAX_MSI_SIZE {
        debug!(name, size, "MSI in cabinet is too large to analyse");
        return None;
    }

    let mut data = Vec::with_capacity(size as usize);
    cabinet.read_file(name).ok()?.read_to_end(&mut data).ok()?;

    Msi::new(Cursor::new(data))
        .inspect_err(|error| debug!(name, %error, "Failed to analyse MSI in cabinet"))
        .ok()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{is_msi, trim_current_dir};

    #[rstest]
    #[case(r".\.\.\Setup.exe", "Setup.exe")]
    #[case("./install.exe", "install.exe")]
    #[case(r".\1033\eula.rtf", r"1033\eula.rtf")]
    #[case("vc_red.msi", "vc_red.msi")]
    fn trims_current_dir(#[case] name: &str, #[case] expected: &str) {
        assert_eq!(trim_current_dir(name), expected);
    }

    #[rstest]
    #[case("vc_red.msi", true)]
    #[case(r".\.\.\VC_Red_x86\vc_red.MSI", true)]
    #[case("vc_red.cab", false)]
    #[case("msp_kb2565063.msp", false)]
    fn msi_extension(#[case] name: &str, #[case] expected: bool) {
        assert_eq!(is_msi(name), expected);
    }
}
