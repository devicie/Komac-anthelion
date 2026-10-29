use serde::Deserialize;

// https://docs.revenera.com/installshield28helplib/helplibrary/SetupIni.htm
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetupIni {
    pub startup: Startup,
    pub languages: Option<Languages>,
}

impl SetupIni {
    /// The section and key names that are used, as they're spelled in the structs.
    const NAMES: [&str; 13] = [
        "Startup",
        "Languages",
        "CmdLine",
        "ScriptDriven",
        "CompanyName",
        "PackageName",
        "Product",
        "AppName",
        "ProductCode",
        "ProductGUID",
        "ProductVersion",
        "UpgradeCode",
        "Default",
    ];

    /// Parses a `Setup.ini`, whose section and key names are case-insensitive.
    pub fn from_str(content: &str) -> Result<Self, serini::Error> {
        let canonical_name = |name: &str| {
            Self::NAMES
                .into_iter()
                .find(|canonical| canonical.eq_ignore_ascii_case(name.trim()))
        };

        let content = content
            .lines()
            .map(|line| {
                if let Some(section) = line
                    .trim_start()
                    .strip_prefix('[')
                    .and_then(|line| line.split_once(']'))
                    .and_then(|(section, _)| canonical_name(section))
                {
                    return format!("[{section}]");
                }

                if let Some((key, value)) = line.split_once('=')
                    && let Some(key) = canonical_name(key)
                {
                    return format!("{key}={value}");
                }

                line.to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n");

        serini::from_str(&content)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Startup {
    pub cmd_line: Option<String>,
    // 0=BasicMsi, InstallScript, BasicMsiWithInstallScript, Unknown, InstallScriptUnicode
    pub script_driven: Option<String>,
    pub company_name: Option<String>,
    pub package_name: Option<String>,
    #[serde(alias = "AppName")]
    pub product: Option<String>,
    #[serde(alias = "ProductGUID")]
    pub product_code: Option<String>,
    pub product_version: Option<String>,
    pub upgrade_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Languages {
    pub default: String,
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::SetupIni;

    #[test]
    fn parses_lowercase_keys_and_empty_cmd_line() {
        // From AVerMedia RECentral's setup.exe
        const SETUP_INI: &str = indoc! {"
            [Info]
            Name=INTL
            Version=1.00.000
            DiskSpace=8000\t;DiskSpace requirement in KB

            [Startup]
            CmdLine=
            SuppressWrongOS=Y
            ScriptDriven=1
            Product=AVerMedia RECentral
            PackageName=AVerMedia RECentral.msi
            ProductCode={30D6B6ED-E039-4D62-8E07-E058D17A9372}
            ProductVersion=1.3.0.118.2019091701

            [Languages]
            count=13
            default=409
            key0=404
        "};

        let setup_ini = SetupIni::from_str(SETUP_INI).unwrap();

        assert_eq!(
            setup_ini.startup.product.as_deref(),
            Some("AVerMedia RECentral")
        );
        assert_eq!(
            setup_ini.startup.product_code.as_deref(),
            Some("{30D6B6ED-E039-4D62-8E07-E058D17A9372}")
        );
        assert_eq!(setup_ini.languages.unwrap().default, "409");
    }

    #[test]
    fn cmd_line_and_languages_are_optional() {
        const SETUP_INI: &str = indoc! {"
            [Startup]
            ScriptDriven=0
            Product=Test
        "};

        let setup_ini = SetupIni::from_str(SETUP_INI).unwrap();

        assert_eq!(setup_ini.startup.cmd_line, None);
        assert_eq!(setup_ini.languages, None);
    }
}
