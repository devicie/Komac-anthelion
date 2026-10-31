use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, KnownLayout};

#[derive(Copy, Clone, Debug, PartialEq, Eq, FromBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct HeaderFlags(u32);

bitflags! {
    impl HeaderFlags: u32 {
        const UNINSTALL = 1u32.to_le();
        const SILENT = (1u32 << 1).to_le();
        const NO_CRC = (1u32 << 2).to_le();
        const FORCE_CRC = (1u32 << 3).to_le();
        /// Set by every nsisbi version (`FH_FLAGS_LARGE_DATABLOCK_OFFSET` before 3.12.1,
        /// `FH_FLAGS_NSISBI_INSTALL` after). The nsisbi flags after it differ between versions.
        const NSISBI = (1u32 << 4).to_le();
    }
}
