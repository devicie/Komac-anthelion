use std::fmt;

use itertools::Either;
use quick_xml::de::from_str;
use serde::Deserialize;
use tracing::{debug, trace};
use zerocopy::{FromBytes, LE, U16};

use super::{state::NsisState, strings::code::NsCode};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NsisVersion {
    major: u8,
    minor: u8,
    park: bool,
}

impl NsisVersion {
    /// Creates a new NSIS version from a major and minor part.
    #[inline]
    pub const fn new(major: u8, minor: u8) -> Self {
        Self {
            major,
            minor,
            park: false,
        }
    }

    #[inline]
    pub const fn v3() -> Self {
        Self::new(3, 0)
    }

    #[inline]
    pub const fn v2() -> Self {
        Self::new(2, 0)
    }

    /// Jim Park's Unicode fork of NSIS 2, the last release of which was 2.46.5.
    #[inline]
    pub const fn park() -> Self {
        Self {
            major: 2,
            minor: 46,
            park: true,
        }
    }

    #[inline]
    pub const fn is_v3(self) -> bool {
        self.major >= 3
    }

    #[inline]
    pub const fn is_v2(self) -> bool {
        !self.is_v3()
    }

    #[inline]
    pub const fn is_park(self) -> bool {
        self.park
    }

    pub fn from_manifest(manifest: &str) -> Option<Self> {
        #[derive(Deserialize)]
        struct Assembly<'data> {
            #[serde(borrow)]
            description: Description<'data>,
        }

        #[derive(Deserialize)]
        struct Description<'data> {
            #[serde(rename = "$text")]
            inner: &'data str,
        }

        from_str::<Assembly>(manifest)
            .ok()
            .map(|assembly| assembly.description.inner)
            .inspect(|description| debug!(manifest.description = description))
            .and_then(Self::from_text)
    }

    pub fn from_branding_text(state: &NsisState) -> Option<Self> {
        let branding_text = state.get_string(state.language_table.branding_offset()?);
        debug!(%branding_text);
        Self::from_text(&branding_text)
    }

    fn from_text(text: &str) -> Option<Self> {
        const NULLSOFT_INSTALL_SYSTEM: &str = "Nullsoft Install System";

        let (text, version) = text.rsplit_once(' ')?;

        if text.trim() != NULLSOFT_INSTALL_SYSTEM {
            return None;
        }

        let (version, suffix) = version.split_once('-').unwrap_or((version, ""));

        let mut parts = version
            .trim_start_matches('v')
            .split('.')
            .flat_map(str::parse::<u8>);

        let major = parts.next()?;
        let minor = parts.next()?;

        Some(Self {
            major,
            minor,
            // Jim Park's fork of NSIS 2 marks its builds as either Unicode or ANSI
            park: major == 2
                && suffix
                    .split('-')
                    .any(|part| matches!(part, "Unicode" | "ANSI")),
        })
    }

    pub fn detect(strings_block: &[u8]) -> Self {
        trace!("Detecting version from strings block");

        // The strings block starts with a UTF-16 null byte if it is Unicode
        let unicode = &strings_block[..size_of::<u16>()] == b"\0\0";

        debug!(%unicode);

        let mut nsis3_count = 0;
        let mut nsis2_count = 0;
        let mut park_count = 0;

        let codes = if unicode {
            assert_eq!(strings_block.len() % size_of::<u16>(), 0);

            Either::Left(
                <[U16<LE>]>::ref_from_bytes(strings_block)
                    .unwrap_or_else(|cast_error| unreachable!("{cast_error}"))
                    .array_windows::<2>()
                    .filter(|window| window[0] == U16::ZERO)
                    .map(|window| window[1].get()),
            )
        } else {
            Either::Right(
                strings_block
                    .array_windows::<2>()
                    .filter_map(|window| (window[0] == 0).then_some(u16::from(window[1]))),
            )
        };

        for code in codes {
            if unicode && NsCode::try_from_park(code).is_some() {
                park_count += 1;
            } else if NsCode::is_code(code, Self::v3()) {
                nsis3_count += 1;
            } else if NsCode::is_code(code, Self::v2()) {
                nsis2_count += 1;
            }
        }

        debug!(nsis3_count, nsis2_count, park_count);

        // Original NSIS 2 doesn't support Unicode, so Unicode strings are either NSIS 3 or Park
        if unicode && park_count > nsis3_count {
            Self::park()
        } else if nsis3_count >= nsis2_count {
            Self::v3()
        } else {
            Self::v2()
        }
    }
}

impl Default for NsisVersion {
    fn default() -> Self {
        Self::v3()
    }
}

impl fmt::Display for NsisVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.major, self.minor)
    }
}

impl PartialEq<f32> for NsisVersion {
    #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn eq(&self, other: &f32) -> bool {
        let major = *other as u8;
        let minor = (other.fract() * 100.0).round() as u8;
        self.major == major && self.minor == minor
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;
    use zerocopy::IntoBytes;

    use super::NsisVersion;

    #[test]
    fn version_from_manifest() {
        const MANIFEST: &str = indoc! {r#"
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <assembly
                xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
                <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="Nullsoft.NSIS.exehead" type="win32"/>
                <description>Nullsoft Install System v3.09</description>
            </assembly>
        "#};

        assert_eq!(
            NsisVersion::from_manifest(MANIFEST).unwrap(),
            NsisVersion::new(3, 9)
        );
    }

    #[rstest]
    #[case("Nullsoft Install System v2.46.5-Unicode", NsisVersion::park())]
    #[case("Nullsoft Install System v2.46-Unicode", NsisVersion::park())]
    #[case("Nullsoft Install System v2.44-Unicode", NsisVersion { major: 2, minor: 44, park: true })]
    #[case("Nullsoft Install System v2.46.5-ANSI", NsisVersion::park())]
    #[case("Nullsoft Install System v2.46.5-Unicode-logging", NsisVersion::park())]
    #[case("Nullsoft Install System v2.46", NsisVersion::new(2, 46))]
    #[case("Nullsoft Install System v2.46-7", NsisVersion::new(2, 46))]
    #[case("Nullsoft Install System v3.0-Unicode", NsisVersion::new(3, 0))]
    #[case("Nullsoft Install System v3.11", NsisVersion::new(3, 11))]
    fn version_from_text(#[case] text: &str, #[case] expected: NsisVersion) {
        assert_eq!(NsisVersion::from_text(text), Some(expected));
    }

    #[test]
    fn detect_park() {
        const STRINGS: [u16; 12] = [
            0,
            0xE001,
            0x8015,
            0,
            0xE002,
            0x8026,
            0,
            b'A' as u16,
            0,
            0xE003,
            0x8001,
            0,
        ];

        assert_eq!(NsisVersion::detect(STRINGS.as_bytes()), NsisVersion::park());
    }

    #[test]
    fn detect_nsis_3_unicode() {
        const STRINGS: [u16; 8] = [0, 3, 0x8095, 0, 2, 0x8026, 0, 0];

        assert_eq!(NsisVersion::detect(STRINGS.as_bytes()), NsisVersion::v3());
    }

    #[test]
    fn detect_nsis_3() {
        const STRINGS_BLOCK: &[u8; 25] = b"\0\x02Shell\0\x04Skip\0\x01Lang\0\x03Var\0";

        assert_eq!(NsisVersion::detect(STRINGS_BLOCK), NsisVersion::v3());
    }

    #[test]
    fn detect_nsis_2() {
        const STRINGS_BLOCK: &[u8; 25] = b"\0\xFEShell\0\xFCSkip\0\xFFLang\0\xFDVar\0";

        assert_eq!(NsisVersion::detect(STRINGS_BLOCK), NsisVersion::v2());
    }

    #[rstest]
    #[case(NsisVersion::new(3, 11), 3.11)]
    #[case(NsisVersion::new(3, 9), 3.09)]
    fn compare_version_with_f32(#[case] nsis_version: NsisVersion, #[case] other: f32) {
        assert_eq!(nsis_version, other);
    }
}
