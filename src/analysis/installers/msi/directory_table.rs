use std::{
    borrow::Cow,
    io,
    io::{Read, Seek},
};

use camino::Utf8PathBuf;
use indexmap::{
    IndexMap,
    map::{Iter, Keys},
};
use msi::{Package, Select};

use super::property_table::PropertyTable;
use crate::analysis::installers::utils::{
    RELATIVE_APP_DATA, RELATIVE_COMMON_FILES_32, RELATIVE_COMMON_FILES_64, RELATIVE_LOCAL_APP_DATA,
    RELATIVE_PROGRAM_FILES_32, RELATIVE_PROGRAM_FILES_64, RELATIVE_TEMP_FOLDER,
    RELATIVE_WINDOWS_DIR,
};

/// Represents the [Windows Installer Directory Table](https://learn.microsoft.com/windows/win32/msi/directory-table),
/// which defines the logical and physical directory layout of an MSI package.
///
/// Each entry in the Directory Table describes both a **source** and **target** directory.
/// The table forms a hierarchy using parent–child relationships defined by the `Directory`
/// and `Directory_Parent` columns.
///
/// The underlying data is stored as an ordered map of:
///
/// ```text
/// Directory identifier → (Optional parent directory identifier, default directory name)
/// ```
///
/// # Structure
///
/// | Column            | Description |
/// |-------------------|--------------|
/// | **`Directory`**     | Unique identifier (or property name) for this directory. |
/// | **`Directory_Parent`** | Identifier of the parent directory, or `NULL` if this is the root. |
/// | **`DefaultDir`**    | The directory name (may be `target:source` or `short|long` form). |
///
/// # Example
///
/// ```text
/// Directory          Directory_Parent   DefaultDir
/// ---------------------------------------------------------
/// TARGETDIR          TARGETDIR          SourceDir
/// ProgramFilesFolder TARGETDIR          .:ProgramFiles
/// MyAppDir           ProgramFilesFolder MyApp
/// ```
///
/// In this example:
/// - `TARGETDIR` is the root.
/// - `ProgramFilesFolder` is a subdirectory of `TARGETDIR`.
/// - `MyAppDir` is a subdirectory of `ProgramFilesFolder`.
///
/// # Notes
///
/// - Only one root directory (`TARGETDIR`) may exist.
/// - Directory resolution occurs during the MSI `CostFinalize` action.
/// - The `DefaultDir` value defines the subdirectory name under the parent directory.
/// - Certain MSI properties (e.g., `ProgramFilesFolder`, `AppDataFolder`) map to system locations.
///
/// This type provides helper functions to construct a directory hierarchy and to
/// resolve MSI directory identifiers into concrete paths.
///
/// See also:
/// - [Using the Directory Table](https://learn.microsoft.com/windows/win32/msi/using-the-directory-table)
/// - [Property Reference](https://learn.microsoft.com/windows/win32/msi/property-reference)
#[derive(Clone, Debug)]
pub struct DirectoryTable(IndexMap<String, (Option<String>, String)>);

impl DirectoryTable {
    pub fn new<R: Read + Seek>(
        msi: &mut Package<R>,
        property_table: &PropertyTable,
    ) -> io::Result<Self> {
        const DIRECTORY: &str = "Directory";
        const DIRECTORY_PARENT: &str = "Directory_Parent";
        const DEFAULT_DIR: &str = "DefaultDir";

        let mut directories = msi
            .select_rows(Select::table(DIRECTORY))?
            .filter_map(|row| {
                match (
                    row[DIRECTORY].as_str(),
                    row[DIRECTORY_PARENT].as_str(),
                    row[DEFAULT_DIR].as_str().map(target_name),
                ) {
                    (Some(directory), parent, Some(default)) => Some((
                        directory.to_owned(),
                        (
                            parent.map(str::to_owned),
                            expand_properties(default, property_table).into_owned(),
                        ),
                    )),
                    _ => None,
                }
            })
            .collect::<IndexMap<String, (Option<String>, String)>>();

        // Advanced Installer names its install directory after its identifier, such as
        // `APPDIR:.`, and sets it with a custom action instead
        for (directory, value) in directory_custom_actions(msi)? {
            let Some((parent, default_dir)) = directories.get_mut(&directory) else {
                continue;
            };

            if *default_dir != directory {
                continue;
            }

            if let Some(path) = expand_formatted_path(&value, property_table) {
                *parent = Some(TARGET_DIR.to_owned());
                *default_dir = path;
            }
        }

        Ok(Self(directories))
    }

    /// Constructs a path from the root directory to the target subdirectory based on the directory
    /// table.
    ///
    /// This is deliberately recursive so that the function can start at the deepest directory,
    /// traverse upwards, and then build the path sequentially as the stack is unwinding. Using a
    /// loop would require the path components to be reversed at the end.
    ///
    /// [Using the Directory Table](https://learn.microsoft.com/windows/win32/msi/using-the-directory-table)
    pub fn build_directory(&self, current_dir: &str, target_dir: &str) -> Option<Utf8PathBuf> {
        // If the current directory is the target, return an empty path
        if current_dir == target_dir {
            return Some(Utf8PathBuf::new());
        }

        if let Some((Some(parent), default_dir)) = self.0.get(current_dir)
            && let Some(mut path) = self.build_directory(parent, target_dir)
        {
            let name = get_property_relative_path(current_dir).unwrap_or(default_dir);
            if name != "." {
                path.push(name);
            }
            return Some(path);
        }

        None
    }

    /// Returns an iterator over all directory identifiers (the `Directory` column) in the order
    /// they appear in the MSI table.
    /// #[inline]
    pub fn keys(&self) -> Keys<'_, String, (Option<String>, String)> {
        self.0.keys()
    }

    /// Returns an iterator over all `(Directory, (Directory_Parent, DefaultDir))` pairs in their
    /// original order.
    #[inline]
    pub fn iter(&self) -> Iter<'_, String, (Option<String>, String)> {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a DirectoryTable {
    type Item = (&'a String, &'a (Option<String>, String));

    type IntoIter = Iter<'a, String, (Option<String>, String)>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
impl<'a> FromIterator<(&'a str, Option<&'a str>, &'a str)> for DirectoryTable {
    fn from_iter<T: IntoIterator<Item = (&'a str, Option<&'a str>, &'a str)>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|(directory, parent, default_dir)| {
                    (
                        directory.to_owned(),
                        (parent.map(str::to_owned), default_dir.to_owned()),
                    )
                })
                .collect(),
        )
    }
}

const TARGET_DIR: &str = "TARGETDIR";

/// Returns the long target directory name of a `DefaultDir` value, which has the format
/// `[targetShort|]targetLong[:[sourceShort|]sourceLong]`. A name of `.` means the parent directory.
///
/// <https://learn.microsoft.com/windows/win32/msi/defaultdir>
fn target_name(default_dir: &str) -> &str {
    let target = default_dir
        .split_once(':')
        .map_or(default_dir, |(target, _source)| target);
    target.split_once('|').map_or(target, |(_short, long)| long)
}

/// Returns the values that custom actions set directories to, in the order they're executed.
///
/// These are type 35 (Directory) and type 51 (Property) custom actions, whose source is the
/// directory and whose target is the formatted value.
///
/// <https://learn.microsoft.com/windows/win32/msi/custom-action-type-35>
fn directory_custom_actions<R: Read + Seek>(
    msi: &mut Package<R>,
) -> io::Result<Vec<(String, String)>> {
    const CUSTOM_ACTION: &str = "CustomAction";
    const INSTALL_EXECUTE_SEQUENCE: &str = "InstallExecuteSequence";
    const BASE_TYPE_MASK: i32 = 0x3F;
    const DIRECTORY_TYPE: i32 = 35;
    const PROPERTY_TYPE: i32 = 51;

    if !msi.has_table(CUSTOM_ACTION) {
        return Ok(Vec::new());
    }

    let sequence = if msi.has_table(INSTALL_EXECUTE_SEQUENCE) {
        msi.select_rows(Select::table(INSTALL_EXECUTE_SEQUENCE))?
            .filter_map(|row| {
                Some((
                    row["Action"].as_str()?.to_owned(),
                    row["Sequence"].as_int()?,
                ))
            })
            .collect::<IndexMap<_, _>>()
    } else {
        IndexMap::new()
    };

    let mut custom_actions = msi
        .select_rows(Select::table(CUSTOM_ACTION))?
        .filter_map(|row| {
            let r#type = row["Type"].as_int()? & BASE_TYPE_MASK;
            (r#type == DIRECTORY_TYPE || r#type == PROPERTY_TYPE).then(|| {
                Some((
                    row["Action"].as_str()?.to_owned(),
                    row["Source"].as_str()?.to_owned(),
                    row["Target"].as_str()?.to_owned(),
                ))
            })?
        })
        .collect::<Vec<_>>();

    // Unsequenced custom actions run when they're called, so they're sorted last
    custom_actions.sort_by_key(|(action, ..)| sequence.get(action).copied().unwrap_or(i32::MAX));

    Ok(custom_actions
        .into_iter()
        .map(|(_action, source, target)| (source, target))
        .collect())
}

/// Expands a formatted path, such as `[ProgramFiles64Folder][Manufacturer]\[ProductName]`,
/// returning [`None`] if it references a property that isn't known.
fn expand_formatted_path(value: &str, property_table: &PropertyTable) -> Option<String> {
    let mut path = String::new();
    let mut rest = value;

    while let Some(start) = rest.find('[') {
        path.push_str(&rest[..start]);
        let end = start + rest[start..].find(']')?;
        let property = &rest[start + 1..end];
        if let Some(folder) = get_property_relative_path(property) {
            // Folder properties end with a path separator
            path.push_str(folder);
            path.push('\\');
        } else {
            path.push_str(property_table.get(property)?);
        }
        rest = &rest[end + 1..];
    }
    path.push_str(rest);

    Some(path.trim_end_matches('\\').to_owned())
}

/// Expands `[Property]` references in a directory name, such as the `[ApplicationFolderName]` that
/// WiX's `WixUI_Advanced` names the install directory with.
fn expand_properties<'a>(default_dir: &'a str, property_table: &PropertyTable) -> Cow<'a, str> {
    let mut default_dir = Cow::Borrowed(default_dir);
    let mut offset = 0;

    while let Some(start) = default_dir[offset..].find('[').map(|index| offset + index)
        && let Some(end) = default_dir[start..].find(']').map(|index| start + index)
    {
        offset = match property_table.get(&default_dir[start + 1..end]) {
            Some(value) => {
                default_dir.to_mut().replace_range(start..=end, value);
                start + value.len()
            }
            None => end + 1,
        };
    }

    default_dir
}

pub fn get_property_relative_path(property: &str) -> Option<&str> {
    const PROGRAM_FILES_64_FOLDER: &str = "ProgramFiles64Folder";
    const PROGRAM_FILES_FOLDER: &str = "ProgramFilesFolder";
    const COMMON_FILES_64_FOLDER: &str = "CommonFiles64Folder";
    const COMMON_FILES_FOLDER: &str = "CommonFilesFolder";
    const APP_DATA_FOLDER: &str = "AppDataFolder";
    const LOCAL_APP_DATA_FOLDER: &str = "LocalAppDataFolder";
    const TEMP_FOLDER: &str = "TempFolder";
    const WINDOWS_FOLDER: &str = "WindowsFolder";

    match property {
        PROGRAM_FILES_64_FOLDER => Some(RELATIVE_PROGRAM_FILES_64),
        PROGRAM_FILES_FOLDER => Some(RELATIVE_PROGRAM_FILES_32),
        COMMON_FILES_64_FOLDER => Some(RELATIVE_COMMON_FILES_64),
        COMMON_FILES_FOLDER => Some(RELATIVE_COMMON_FILES_32),
        APP_DATA_FOLDER => Some(RELATIVE_APP_DATA),
        LOCAL_APP_DATA_FOLDER => Some(RELATIVE_LOCAL_APP_DATA),
        TEMP_FOLDER => Some(RELATIVE_TEMP_FOLDER),
        WINDOWS_FOLDER => Some(RELATIVE_WINDOWS_DIR),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{PropertyTable, expand_formatted_path, expand_properties, target_name};

    #[rstest]
    #[case::long_name("PROGRA~1|ProgramFiles", "ProgramFiles")]
    #[case::target_and_source("APPDIR:.", "APPDIR")]
    #[case::short_long_target_and_source("MYAPP~1|My App:Source", "My App")]
    #[case::parent("SourceDir", "SourceDir")]
    #[case::dot(".", ".")]
    fn target_name_of_default_dir(#[case] default_dir: &str, #[case] expected: &str) {
        assert_eq!(target_name(default_dir), expected);
    }

    #[rstest]
    #[case::advanced_installer(
        r"[ProgramFiles64Folder][Manufacturer]\[ProductName]",
        Some(r"%ProgramFiles%\Kuta Software LLC\Infinite Calculus")
    )]
    #[case::trailing_folder("[LocalAppDataFolder]", Some("%LocalAppData%"))]
    #[case::unknown_property(r"[ProgramFilesFolder][Unknown]", None)]
    #[case::unclosed_bracket(r"[ProgramFilesFolder", None)]
    fn expands_formatted_path(#[case] value: &str, #[case] expected: Option<&str>) {
        let property_table = PropertyTable::from_iter([
            ("Manufacturer", "Kuta Software LLC"),
            ("ProductName", "Infinite Calculus"),
        ]);

        assert_eq!(
            expand_formatted_path(value, &property_table).as_deref(),
            expected
        );
    }

    #[rstest]
    #[case::no_reference("MyApp", "MyApp")]
    #[case::whole_name("[AppName]", "My App")]
    #[case::within_name("Vendor [AppName] 2", "Vendor My App 2")]
    #[case::unknown_property("[Unknown]", "[Unknown]")]
    #[case::unclosed_bracket("[AppName", "[AppName")]
    #[case::self_reference("[Recursive]", "[Recursive]")]
    fn expands_property_references(#[case] default_dir: &str, #[case] expected: &str) {
        let property_table =
            PropertyTable::from_iter([("AppName", "My App"), ("Recursive", "[Recursive]")]);

        assert_eq!(expand_properties(default_dir, &property_table), expected);
    }
}
