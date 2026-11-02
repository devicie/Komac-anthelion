use const_format::formatcp;
use zerocopy::I32;

use super::super::{
    super::utils::{
        RELATIVE_APP_DATA, RELATIVE_COMMON_FILES_32, RELATIVE_COMMON_FILES_64,
        RELATIVE_LOCAL_APP_DATA, RELATIVE_PROGRAM_DATA, RELATIVE_PROGRAM_FILES_32,
        RELATIVE_PROGRAM_FILES_64, RELATIVE_PUBLIC, RELATIVE_SYSTEM_ROOT, RELATIVE_USER_PROFILE,
        RELATIVE_WINDOWS_DIR,
    },
    entry::ExecFlag,
    state::NsisState,
};

const USER_DESKTOP: &str = formatcp!(r"{RELATIVE_USER_PROFILE}\Desktop");
const USER_DOCUMENTS: &str = formatcp!(r"{RELATIVE_USER_PROFILE}\Documents");
const USER_FAVORITES: &str = formatcp!(r"{RELATIVE_USER_PROFILE}\Favorites");
const USER_MUSIC: &str = formatcp!(r"{RELATIVE_USER_PROFILE}\Music");
const USER_PICTURES: &str = formatcp!(r"{RELATIVE_USER_PROFILE}\Pictures");
const USER_VIDEOS: &str = formatcp!(r"{RELATIVE_USER_PROFILE}\Videos");

const PUBLIC_DESKTOP: &str = formatcp!(r"{RELATIVE_PUBLIC}\Desktop");
const PUBLIC_DOCUMENTS: &str = formatcp!(r"{RELATIVE_PUBLIC}\Documents");
const PUBLIC_MUSIC: &str = formatcp!(r"{RELATIVE_PUBLIC}\Music");
const PUBLIC_PICTURES: &str = formatcp!(r"{RELATIVE_PUBLIC}\Pictures");
const PUBLIC_VIDEOS: &str = formatcp!(r"{RELATIVE_PUBLIC}\Videos");

/// NSIS can use one name for two CSIDL_*** and `CSIDL_COMMON`_*** items (`CurrentUser` / `AllUsers`)
/// Some NSIS shell names are not identical to WIN32 CSIDL_* names.
/// NSIS doesn't use some CSIDL_* values.
///
/// Some values have been adapted to use relative folders for winget.
const STRINGS: &[Option<&str>; 62] = &[
    Some(USER_DESKTOP),
    Some("Internet"),
    Some("SMPrograms"),
    Some("Controls"),
    Some("Printers"),
    Some(USER_DOCUMENTS),
    Some(USER_FAVORITES),
    Some("SMStartup"),
    Some("Recent"),
    Some("SendTo"),
    Some("BitBucket"),
    Some("StartMenu"),
    None,
    Some(USER_MUSIC),
    Some(USER_VIDEOS),
    None,
    Some(USER_DESKTOP),
    Some("Drives"),
    Some("Network"),
    Some("NetHood"),
    Some("Fonts"),
    Some("Templates"),
    Some("StartMenu"),
    Some("SMPrograms"),
    Some("SMStartup"),
    Some(PUBLIC_DESKTOP),
    Some(RELATIVE_APP_DATA),
    Some("PrintHood"),
    Some(RELATIVE_LOCAL_APP_DATA),
    Some("ALTStartUp"),
    Some("ALTStartUp"),
    Some(USER_FAVORITES),
    Some("InternetCache"),
    Some("Cookies"),
    Some("History"),
    Some(RELATIVE_PROGRAM_DATA),
    Some(RELATIVE_WINDOWS_DIR),
    Some(RELATIVE_SYSTEM_ROOT),
    Some(RELATIVE_PROGRAM_FILES_64),
    Some(USER_PICTURES),
    Some(RELATIVE_USER_PROFILE),
    Some("System32"),
    Some(RELATIVE_PROGRAM_FILES_32),
    Some(RELATIVE_COMMON_FILES_64),
    Some(RELATIVE_COMMON_FILES_32),
    Some("Templates"),
    Some(PUBLIC_DOCUMENTS),
    Some("AdminTools"),
    Some("AdminTools"),
    Some("Connections"),
    None,
    None,
    None,
    Some(PUBLIC_MUSIC),
    Some(PUBLIC_PICTURES),
    Some(PUBLIC_VIDEOS),
    Some("Resources"),
    Some("ResourcesLocalized"),
    Some("CommonOEMLinks"),
    Some("CDBurnArea"),
    None,
    Some("ComputersNearMe"),
];

pub struct Shell;

impl Shell {
    /// Adapted from <https://github.com/mcmilk/7-Zip/blob/HEAD/CPP/7zip/Archive/Nsis/NsisIn.cpp#L683>
    pub fn resolve(buf: &mut String, state: &NsisState, character: u16) {
        const PROGRAM_FILES_DIR: &str = "ProgramFilesDir";
        const COMMON_FILES_DIR: &str = "CommonFilesDir";

        let (index1, index2): (u8, u8) = character.to_le_bytes().into();

        if index1 & (1 << 7) != 0 {
            let offset = index1 & 0x3F;
            // A 64-bit process reads the 64-bit registry view even without the 64-bit flag
            let is_64_bit = index1 & (1 << 6) != 0 || state.is_64_bit;
            let shell_string = state.get_string(i32::from(offset));
            if shell_string == PROGRAM_FILES_DIR {
                buf.push_str(if is_64_bit {
                    RELATIVE_PROGRAM_FILES_64
                } else {
                    RELATIVE_PROGRAM_FILES_32
                });
            } else if shell_string == COMMON_FILES_DIR {
                buf.push_str(if is_64_bit {
                    RELATIVE_COMMON_FILES_64
                } else {
                    RELATIVE_COMMON_FILES_32
                });
            }
        } else {
            let is_all_users = state.exec_flags[ExecFlag::ShellVarContext] != I32::ZERO;
            if let Some(shell_str) = Self::folder(index1, index2, is_all_users) {
                buf.push_str(shell_str);
            }
        }
    }

    /// Returns the folder for a shell variable.
    ///
    /// NSIS encodes the CSIDL of the folder for the current user in the low byte and the CSIDL of
    /// the folder for all users in the high byte. The folder for all users is used when the shell
    /// variable context is set to all, falling back to the folder for the current user.
    ///
    /// <https://github.com/NSIS-Dev/nsis/blob/v311/Source/exehead/util.c#L615>
    fn folder(current_user: u8, all_users: u8, is_all_users: bool) -> Option<&'static str> {
        let folder = |csidl: u8| STRINGS.get(usize::from(csidl)).copied().flatten();
        // $WINDIR and $SYSDIR aren't user folders, so their high byte isn't an all users folder
        let (preferred, fallback) = if is_all_users && !matches!(current_user, 36 | 37) {
            (all_users, current_user)
        } else {
            (current_user, all_users)
        };
        folder(preferred).or_else(|| folder(fallback))
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::Shell;

    // CSIDL values
    const DESKTOPDIRECTORY: u8 = 0x10;
    const COMMON_DESKTOPDIRECTORY: u8 = 0x19;
    const PERSONAL: u8 = 0x05;
    const COMMON_DOCUMENTS: u8 = 0x2E;
    const APPDATA: u8 = 0x1A;
    const COMMON_APPDATA: u8 = 0x23;
    const PROFILE: u8 = 0x28;
    const MYPICTURES: u8 = 0x27;
    const COMMON_PICTURES: u8 = 0x36;

    #[rstest]
    #[case(PERSONAL, COMMON_DOCUMENTS, false, r"%UserProfile%\Documents")]
    #[case(PERSONAL, COMMON_DOCUMENTS, true, r"%Public%\Documents")]
    #[case(
        DESKTOPDIRECTORY,
        COMMON_DESKTOPDIRECTORY,
        false,
        r"%UserProfile%\Desktop"
    )]
    #[case(DESKTOPDIRECTORY, COMMON_DESKTOPDIRECTORY, true, r"%Public%\Desktop")]
    #[case(APPDATA, COMMON_APPDATA, false, "%AppData%")]
    #[case(APPDATA, COMMON_APPDATA, true, "%ProgramData%")]
    #[case(MYPICTURES, COMMON_PICTURES, false, r"%UserProfile%\Pictures")]
    #[case(MYPICTURES, COMMON_PICTURES, true, r"%Public%\Pictures")]
    #[case(PROFILE, PROFILE, false, "%UserProfile%")]
    #[case(PROFILE, PROFILE, true, "%UserProfile%")]
    fn folder(
        #[case] current_user: u8,
        #[case] all_users: u8,
        #[case] is_all_users: bool,
        #[case] expected: &str,
    ) {
        assert_eq!(
            Shell::folder(current_user, all_users, is_all_users),
            Some(expected)
        );
    }
}
