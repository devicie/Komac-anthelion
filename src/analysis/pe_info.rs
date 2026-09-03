use std::collections::BTreeMap;

use serde::Serialize;

use crate::analysis::installers::pe::VSVersionInfo;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PeInfo {
    pub fixed_file_info: PeFixedFileInfo,

    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub string_file_info: BTreeMap<String, String>,
}

impl PeInfo {
    pub fn from_version_info(version_info: &VSVersionInfo<'_>) -> Self {
        Self {
            fixed_file_info: PeFixedFileInfo::from(version_info),
            string_file_info: string_file_info_from_entries(version_info.string_table()),
        }
    }

    pub fn file_version(&self) -> Option<&str> {
        Self::dotted(
            self.string_file_info.get("FileVersion"),
            &self.fixed_file_info.file_version,
        )
    }

    pub fn product_version(&self) -> Option<&str> {
        Self::dotted(
            self.string_file_info.get("ProductVersion"),
            &self.fixed_file_info.product_version,
        )
    }

    /// String table versions are often the comma-separated form of the fixed-file-info quad
    /// ("10, 0, 0, 1290"), which is not a valid version. That quad already holds the dotted form.
    fn dotted<'a>(string_version: Option<&'a String>, fixed_version: &'a str) -> Option<&'a str> {
        match string_version {
            Some(version) if version.contains(',') => Some(fixed_version),
            version => version.map(String::as_str),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PeFixedFileInfo {
    pub file_version: String,
    pub product_version: String,
    #[serde(rename = "FileOS")]
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
}

impl From<&VSVersionInfo<'_>> for PeFixedFileInfo {
    fn from(version_info: &VSVersionInfo<'_>) -> Self {
        let fixed_file_info = version_info.fixed;

        Self {
            file_version: format_version(fixed_file_info.file_version_raw()),
            product_version: format_version(fixed_file_info.product_version_raw()),
            file_os: fixed_file_info.file_os(),
            file_type: fixed_file_info.file_type(),
            file_subtype: fixed_file_info.file_subtype(),
        }
    }
}

fn format_version((major, minor, patch, build): (u16, u16, u16, u16)) -> String {
    format!("{major}.{minor}.{patch}.{build}")
}

fn string_file_info_from_entries<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> BTreeMap<String, String> {
    entries
        .into_iter()
        .filter(|(_, value)| !value.trim().is_empty())
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{PeFixedFileInfo, PeInfo, string_file_info_from_entries};

    #[test]
    fn empty_string_file_info_values_are_omitted() {
        let string_file_info = string_file_info_from_entries([
            ("FileVersion", "1.2.3"),
            ("ProductName", ""),
            ("CompanyName", "   "),
        ]);

        assert_eq!(string_file_info.len(), 1);
        assert_eq!(
            string_file_info.get("FileVersion").map(String::as_str),
            Some("1.2.3")
        );
        assert!(!string_file_info.contains_key("ProductName"));
        assert!(!string_file_info.contains_key("CompanyName"));
    }

    fn pe_info(string_product_version: &str) -> PeInfo {
        PeInfo {
            fixed_file_info: PeFixedFileInfo {
                file_version: "10.0.0.1290".to_owned(),
                product_version: "10.0.0.1290".to_owned(),
                file_os: 4,
                file_type: 1,
                file_subtype: 0,
            },
            string_file_info: string_file_info_from_entries([(
                "ProductVersion",
                string_product_version,
            )]),
        }
    }

    #[rstest]
    #[case::comma_separated("10, 0, 0, 1290", Some("10.0.0.1290"))]
    #[case::comma_separated_without_spaces("10,0,0,1290", Some("10.0.0.1290"))]
    #[case::dot_separated("10.0.0.1290", Some("10.0.0.1290"))]
    #[case::not_a_quad("2026 R1", Some("2026 R1"))]
    #[case::absent("", None)]
    fn comma_separated_versions_come_from_fixed_file_info(
        #[case] string_product_version: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(pe_info(string_product_version).product_version(), expected);
    }
}
