use zerocopy::{Immutable, KnownLayout, TryFromBytes, ValidityError, try_transmute};

use crate::analysis::installers::nsis::version::NsisVersion;

#[allow(dead_code)]
#[derive(Copy, Clone, TryFromBytes, KnownLayout, Immutable)]
#[repr(u16)]
pub enum NsCode {
    LangV3 = 1,
    ShellV3 = 2,
    VarV3 = 3,
    SkipV3 = 4,
    SkipV2 = 252,
    VarV2 = 253,
    ShellV2 = 254,
    LangV2 = 255,
    // Jim Park's Unicode fork of NSIS 2 puts its codes in the Unicode private use area, as the
    // NSIS 2 codes are ordinary characters in UTF-16.
    SkipPark = 0xE000,
    VarPark = 0xE001,
    ShellPark = 0xE002,
    LangPark = 0xE003,
}

impl NsCode {
    pub fn try_new_with_version<T>(code: T, version: NsisVersion) -> Option<Self>
    where
        T: TryInto<Self>,
    {
        code.try_into().ok().filter(|code| code.is_version(version))
    }

    #[inline]
    pub const fn is_lang(self) -> bool {
        matches!(self, Self::LangV2 | Self::LangV3 | Self::LangPark)
    }

    #[inline]
    pub const fn is_shell(self) -> bool {
        matches!(self, Self::ShellV2 | Self::ShellV3 | Self::ShellPark)
    }

    #[inline]
    pub const fn is_var(self) -> bool {
        matches!(self, Self::VarV2 | Self::VarV3 | Self::VarPark)
    }

    #[inline]
    pub const fn is_skip(self) -> bool {
        matches!(self, Self::SkipV2 | Self::SkipV3 | Self::SkipPark)
    }

    #[inline]
    pub const fn is_v3(self) -> bool {
        matches!(
            self,
            Self::LangV3 | Self::ShellV3 | Self::VarV3 | Self::SkipV3
        )
    }

    #[inline]
    pub const fn is_v2(self) -> bool {
        matches!(
            self,
            Self::LangV2 | Self::ShellV2 | Self::VarV2 | Self::SkipV2
        )
    }

    #[inline]
    pub const fn is_park(self) -> bool {
        matches!(
            self,
            Self::LangPark | Self::ShellPark | Self::VarPark | Self::SkipPark
        )
    }

    #[inline]
    pub const fn is_version(self, version: NsisVersion) -> bool {
        if version.is_park() {
            self.is_park()
        } else if version.is_v2() {
            self.is_v2()
        } else {
            self.is_v3()
        }
    }

    pub fn is_code<T>(code: T, version: NsisVersion) -> bool
    where
        T: TryInto<Self>,
    {
        code.try_into().is_ok_and(|code| code.is_version(version))
    }
}

impl TryFrom<u16> for NsCode {
    type Error = ValidityError<u16, Self>;

    fn try_from(code: u16) -> Result<Self, Self::Error> {
        try_transmute!(code)
    }
}

impl TryFrom<u8> for NsCode {
    type Error = ValidityError<u16, Self>;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Self::try_from(u16::from(code))
    }
}

#[cfg(test)]
mod tests {
    use super::NsCode;
    use crate::analysis::installers::nsis::version::NsisVersion;

    #[test]
    fn v3() {
        // V3 codes
        assert!(NsCode::LangV3.is_v3());
        assert!(NsCode::ShellV3.is_v3());
        assert!(NsCode::VarV3.is_v3());
        assert!(NsCode::SkipV3.is_v3());

        // V2 codes
        assert!(!NsCode::SkipV2.is_v3());
        assert!(!NsCode::VarV2.is_v3());
        assert!(!NsCode::ShellV2.is_v3());
        assert!(!NsCode::LangV2.is_v3());
    }

    #[test]
    fn v2() {
        // V2 codes
        assert!(NsCode::LangV2.is_v2());
        assert!(NsCode::ShellV2.is_v2());
        assert!(NsCode::VarV2.is_v2());
        assert!(NsCode::SkipV2.is_v2());

        // V3 codes
        assert!(!NsCode::SkipV3.is_v2());
        assert!(!NsCode::VarV3.is_v2());
        assert!(!NsCode::ShellV3.is_v2());
        assert!(!NsCode::LangV3.is_v2());
    }

    #[test]
    fn park() {
        let park = NsisVersion::park(2, 46);

        // Park codes
        assert!(NsCode::SkipPark.is_park());
        assert!(NsCode::VarPark.is_park());
        assert!(NsCode::ShellPark.is_park());
        assert!(NsCode::LangPark.is_park());
        assert!(NsCode::is_code(0xE003u16, park));

        // The NSIS 2 codes are ordinary characters in a Park installer
        assert!(!NsCode::LangV2.is_park());
        assert!(!NsCode::is_code(255u16, park));
        assert!(!NsCode::is_code(1u16, park));

        // Park codes only apply to Park installers
        assert!(!NsCode::is_code(0xE003u16, NsisVersion::v2()));
        assert!(!NsCode::is_code(0xE003u16, NsisVersion::v3()));
    }
}
