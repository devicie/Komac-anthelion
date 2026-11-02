use winget_types::installer::Scope;

pub mod cabinet;
mod lzma_stream_header;
pub use lzma_stream_header::LzmaStreamHeader;

pub const RELATIVE_PROGRAM_FILES_64: &str = "%ProgramFiles%";
pub const RELATIVE_PROGRAM_FILES_32: &str = "%ProgramFiles(x86)%";
pub const RELATIVE_COMMON_FILES_64: &str = "%CommonProgramFiles%";
pub const RELATIVE_COMMON_FILES_32: &str = "%CommonProgramFiles(x86)%";
pub const RELATIVE_LOCAL_APP_DATA: &str = "%LocalAppData%";
pub const RELATIVE_APP_DATA: &str = "%AppData%";
pub const RELATIVE_PROGRAM_DATA: &str = "%ProgramData%";
pub const RELATIVE_WINDOWS_DIR: &str = "%WinDir%";
pub const RELATIVE_SYSTEM_ROOT: &str = "%SystemRoot%";
pub const RELATIVE_SYSTEM_DRIVE: &str = "%SystemDrive%";
pub const RELATIVE_TEMP_FOLDER: &str = "%Temp%";
pub const RELATIVE_USER_PROFILE: &str = "%UserProfile%";
pub const RELATIVE_PUBLIC: &str = "%Public%";

/// Returns the scope implied by an install directory that's relative to a known folder.
///
/// Folders within the user's profile imply a user install, and folders shared by all users imply a
/// machine install. This extends [`Scope::from_install_directory`] with the user profile and public
/// folders.
pub fn install_directory_scope<T: AsRef<str>>(install_directory: T) -> Option<Scope> {
    const USER_DIRECTORIES: [&str; 3] = [
        RELATIVE_APP_DATA,
        RELATIVE_LOCAL_APP_DATA,
        RELATIVE_USER_PROFILE,
    ];
    const MACHINE_DIRECTORIES: [&str; 8] = [
        RELATIVE_PROGRAM_FILES_64,
        RELATIVE_PROGRAM_FILES_32,
        RELATIVE_COMMON_FILES_64,
        RELATIVE_COMMON_FILES_32,
        RELATIVE_PROGRAM_DATA,
        RELATIVE_WINDOWS_DIR,
        RELATIVE_SYSTEM_ROOT,
        RELATIVE_PUBLIC,
    ];

    let install_directory = install_directory.as_ref();

    let is_within = |directory: &&str| {
        install_directory
            .get(..directory.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(directory))
            && install_directory[directory.len()..]
                .chars()
                .next()
                .is_none_or(|char| matches!(char, '\\' | '/'))
    };

    if USER_DIRECTORIES.iter().any(is_within) {
        Some(Scope::User)
    } else if MACHINE_DIRECTORIES.iter().any(is_within) {
        Some(Scope::Machine)
    } else {
        Scope::from_install_directory(install_directory)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use winget_types::installer::Scope;

    use super::install_directory_scope;

    #[rstest]
    #[case(r"%UserProfile%\Documents\App", Some(Scope::User))]
    #[case(r"%userprofile%\App", Some(Scope::User))]
    #[case("%UserProfile%", Some(Scope::User))]
    #[case(r"%AppData%\App", Some(Scope::User))]
    #[case(r"%LocalAppData%\Programs\App", Some(Scope::User))]
    #[case(r"%Public%\Documents\App", Some(Scope::Machine))]
    #[case(r"%ProgramFiles%\App", Some(Scope::Machine))]
    #[case(r"%ProgramFiles(x86)%\App", Some(Scope::Machine))]
    #[case(r"%ProgramData%\App", Some(Scope::Machine))]
    #[case(r"%UserProfileX%\App", None)]
    #[case(r"C:\App", None)]
    fn scope_from_install_directory(#[case] directory: &str, #[case] expected: Option<Scope>) {
        assert_eq!(install_directory_scope(directory), expected);
    }
}
