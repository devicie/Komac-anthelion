//! Support for the entries of installers built with [nsisbi], a fork of NSIS for installers larger
//! than 2 GB.
//!
//! nsisbi entries have 8 parameters instead of 6 so that data offsets can be 64-bit, and it inserts
//! `ExtractStubFile` and `VerifyExternalFile` after `ExtractFile`. Entries are translated to the
//! layout used by [`Entry`] so they can be read like regular NSIS entries. The layout has been the
//! same since at least nsisbi 7423-3 (NSIS 3.10).
//!
//! [nsisbi]: https://sourceforge.net/projects/nsisbi/

use tracing::debug;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, LE, TryFromBytes, U32};

use super::{Entry, NsisError};

/// nsisbi opcodes that differ from the layout used by [`Entry`].
mod opcode {
    pub const EXTRACT_FILE: u32 = 20;
    pub const EXTRACT_STUB_FILE: u32 = 21;
    pub const VERIFY_EXTERNAL_FILE: u32 = 22;
    pub const WRITE_REG: u32 = 53;
    pub const WRITE_UNINSTALLER: u32 = 64;

    /// The number of opcodes inserted after `ExtractFile`.
    pub const NUM_INSERTED: u32 = 2;

    /// `Nop` in the layout used by [`Entry`](super::Entry).
    pub const NOP: u32 = 2;
}

/// An nsisbi entry before it has been translated.
#[derive(Copy, Clone, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct RawEntry {
    opcode: U32<LE>,
    params: [U32<LE>; 8],
}

/// An entry in the layout used by [`Entry`].
#[derive(Copy, Clone, IntoBytes, Immutable)]
#[repr(C)]
struct TranslatedEntry {
    opcode: U32<LE>,
    params: [U32<LE>; 6],
}

impl RawEntry {
    /// Translates the entry to the layout used by [`Entry`], dropping the high parts of 64-bit
    /// data offsets and the CRCs of the data.
    fn translate(self) -> TranslatedEntry {
        let [p0, p1, p2, p3, p4, p5, p6, _] = self.params;
        let zero = U32::ZERO;

        let (opcode, params) = match self.opcode.get() {
            // [overwrite flag, name, offset low, offset high, datetime low, datetime high,
            // allow ignore, crc]
            opcode::EXTRACT_FILE | opcode::EXTRACT_STUB_FILE => {
                (opcode::EXTRACT_FILE, [p0, p1, p2, p4, p5, p6])
            }
            opcode::VERIFY_EXTERNAL_FILE => (opcode::NOP, [zero; 6]),
            // [root, key name, value name, value or offset low, offset high, type, sub type, crc]
            opcode::WRITE_REG => (opcode::WRITE_REG, [p0, p1, p2, p3, p5, p6]),
            // [name, offset low, offset high, icon size, alternative path, icon crc, data crc]
            opcode::WRITE_UNINSTALLER => (opcode::WRITE_UNINSTALLER, [p0, p1, p3, p4, zero, zero]),
            opcode => (opcode, [p0, p1, p2, p3, p4, p5]),
        };

        let opcode = if opcode > opcode::VERIFY_EXTERNAL_FILE {
            opcode - opcode::NUM_INSERTED
        } else {
            opcode
        };

        TranslatedEntry {
            opcode: opcode.into(),
            params,
        }
    }
}

/// Reads the entries from the entries block, translating them to the layout used by [`Entry`].
pub fn read_entries(entries_block: &[u8]) -> Result<Vec<Entry>, NsisError> {
    let raw_entries = <[RawEntry]>::ref_from_bytes(entries_block)
        .map_err(|error| NsisError::ZeroCopy(error.to_string()))?;

    Ok(raw_entries
        .iter()
        .map(|raw_entry| {
            let entry = raw_entry.translate();
            Entry::try_read_from_bytes(entry.as_bytes()).unwrap_or_else(|_| {
                debug!(
                    opcode = raw_entry.opcode.get(),
                    "Entry has invalid parameters for its opcode"
                );
                Entry::Invalid
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{Entry, read_entries};

    fn raw_entry(opcode: u32, params: [u32; 8]) -> Vec<u8> {
        [opcode]
            .iter()
            .chain(&params)
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    #[test]
    fn shifts_opcodes_after_inserted() {
        // nsisbi `Return` (1), `VerifyExternalFile` (22) and `Quit` (4)
        let block = [
            raw_entry(1, [0; 8]),
            raw_entry(22, [5, 0, 0, 0, 0, 0, 0, 0]),
            raw_entry(4, [0; 8]),
        ]
        .concat();

        let entries = read_entries(&block).unwrap();
        assert_eq!(entries[0], Entry::Return);
        assert!(matches!(entries[1], Entry::Jump { address } if address.get() == 0));
        assert_eq!(entries[2], Entry::Quit);
    }

    #[test]
    fn extract_file() {
        let block = raw_entry(20, [1, 2, 3, 0, u32::MAX, u32::MAX, 1, 0xDEAD]);

        let entries = read_entries(&block).unwrap();
        let Entry::ExtractFile {
            name,
            position,
            datetime,
            allow_ignore,
            ..
        } = entries[0]
        else {
            panic!("Expected ExtractFile, got {:?}", entries[0]);
        };
        assert_eq!(name.get(), 2);
        assert_eq!(position.get(), 3);
        assert_eq!(datetime.get(), u64::MAX);
        assert_eq!(allow_ignore.get(), 1);
    }

    #[test]
    fn write_reg_string() {
        // nsisbi `WriteReg` is 53, which is 51 in the NSIS layout
        let block = raw_entry(53, [0x8000_0002, 2, 3, 4, 0, 1, 1, 0]);

        let entries = read_entries(&block).unwrap();
        let Entry::WriteReg { value, .. } = entries[0] else {
            panic!("Expected WriteReg, got {:?}", entries[0]);
        };
        assert_eq!(value.get(), 4);
    }
}
