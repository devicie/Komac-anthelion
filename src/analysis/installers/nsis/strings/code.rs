use std::num::TryFromIntError;

use itertools::Either;
use zerocopy::{Immutable, KnownLayout, TryFromBytes, ValidityError, try_transmute};

use crate::analysis::installers::nsis::version::NsisVersion;

#[allow(dead_code)]
#[derive(Copy, Clone, TryFromBytes, KnownLayout, Immutable)]
#[repr(u8)]
pub enum NsCode {
    LangV3 = 1,
    ShellV3 = 2,
    VarV3 = 3,
    SkipV3 = 4,
    SkipV2 = 252,
    VarV2 = 253,
    ShellV2 = 254,
    LangV2 = 255,
}

impl NsCode {
    /// Jim Park's Unicode fork of NSIS 2 moves the NSIS 2 codes into the Unicode Private Use Area,
    /// keeping their order.
    ///
    /// <https://github.com/mcmilk/7-Zip/blob/HEAD/CPP/7zip/Archive/Nsis/NsisIn.cpp#L659>
    const PARK_SKIP: u16 = 0xE000;

    /// Returns the code for a character in a Unicode NSIS Park strings block.
    pub fn try_from_park(code: u16) -> Option<Self> {
        code.checked_sub(Self::PARK_SKIP)
            .and_then(|offset| u8::try_from(offset).ok())
            .and_then(|offset| (Self::SkipV2 as u8).checked_add(offset))
            .and_then(|code| Self::try_from(code).ok())
    }

    pub fn try_new_with_version<T>(code: T, version: NsisVersion) -> Option<Self>
    where
        T: TryInto<Self>,
    {
        code.try_into().ok().filter(|code| code.is_version(version))
    }

    #[inline]
    pub const fn is_lang(self) -> bool {
        matches!(self, Self::LangV2 | Self::LangV3)
    }

    #[inline]
    pub const fn is_shell(self) -> bool {
        matches!(self, Self::ShellV2 | Self::ShellV3)
    }

    #[inline]
    pub const fn is_var(self) -> bool {
        matches!(self, Self::VarV2 | Self::VarV3)
    }

    #[inline]
    pub const fn is_skip(self) -> bool {
        matches!(self, Self::SkipV2 | Self::SkipV3)
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
    pub const fn is_version(self, version: NsisVersion) -> bool {
        (self.is_v3() && version.is_v3()) || (self.is_v2() && version.is_v2())
    }

    pub fn is_code<T>(code: T, version: NsisVersion) -> bool
    where
        T: TryInto<Self>,
    {
        code.try_into().is_ok_and(|code| code.is_version(version))
    }
}

impl TryFrom<u8> for NsCode {
    type Error = ValidityError<u8, Self>;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        try_transmute!(code)
    }
}

impl TryFrom<u16> for NsCode {
    type Error = Either<TryFromIntError, ValidityError<u8, Self>>;

    fn try_from(code: u16) -> Result<Self, Self::Error> {
        u8::try_from(code)
            .map_err(Either::Left)
            .and_then(|code| Self::try_from(code).map_err(Either::Right))
    }
}

#[cfg(test)]
mod tests {
    use super::NsCode;

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
        assert!(NsCode::try_from_park(0xE000).is_some_and(NsCode::is_skip));
        assert!(NsCode::try_from_park(0xE001).is_some_and(NsCode::is_var));
        assert!(NsCode::try_from_park(0xE002).is_some_and(NsCode::is_shell));
        assert!(NsCode::try_from_park(0xE003).is_some_and(NsCode::is_lang));

        assert!(NsCode::try_from_park(0xDFFF).is_none());
        assert!(NsCode::try_from_park(0xE004).is_none());
        assert!(NsCode::try_from_park(u16::from(b'A')).is_none());
        assert!(NsCode::try_from_park(u16::from(NsCode::VarV2 as u8)).is_none());
        assert!(NsCode::try_from_park(u16::from(NsCode::VarV3 as u8)).is_none());
    }
}
