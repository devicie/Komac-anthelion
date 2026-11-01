/// Small files from beside the file being analysed, such as from the same folder of a ZIP.
///
/// Some installers keep their settings beside themselves instead of embedding them, such as an
/// InstallShield setup launcher that reads `setup.ini` from its own folder.
#[derive(Debug, Default)]
pub struct SiblingFiles(Vec<(String, Vec<u8>)>);

impl SiblingFiles {
    /// The names of the files that are worth reading from beside an installer, compared
    /// case-insensitively.
    pub const NAMES: [&str; 2] = ["setup.ini", "setup.iss"];

    /// The largest sibling file that is read, as the files are only small settings files.
    pub const MAX_SIZE: u64 = 1024 * 1024;

    /// Returns `true` if a file with the given name is worth reading from beside an installer.
    pub fn is_wanted(name: &str) -> bool {
        Self::NAMES
            .iter()
            .any(|wanted| wanted.eq_ignore_ascii_case(name))
    }

    pub fn push(&mut self, name: String, data: Vec<u8>) {
        self.0.push((name, data));
    }

    /// Returns the contents of the sibling file with the given name, compared case-insensitively.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(file_name, _)| file_name.eq_ignore_ascii_case(name))
            .map(|(_, data)| data.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::SiblingFiles;

    #[test]
    fn gets_file_case_insensitively() {
        let mut siblings = SiblingFiles::default();
        siblings.push("Setup.ini".to_owned(), b"[Startup]".to_vec());

        assert_eq!(siblings.get("setup.ini"), Some(b"[Startup]".as_slice()));
        assert_eq!(siblings.get("setup.iss"), None);
    }

    #[test]
    fn wants_installshield_settings_files() {
        assert!(SiblingFiles::is_wanted("SETUP.INI"));
        assert!(SiblingFiles::is_wanted("setup.iss"));
        assert!(!SiblingFiles::is_wanted("data1.cab"));
    }
}
