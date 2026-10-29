//! Support for installers built with Jim Park's Unicode fork of NSIS 2 ("NSIS Park").
//!
//! The fork inserts extra opcodes into the NSIS 2 opcode table, so the raw opcodes of an entry
//! have to be translated to the layout used by [`Entry`] before the entry can be read. Which
//! opcodes are inserted depends on the Park release and whether logging was enabled when the
//! installer was compiled, neither of which is stored in the installer, so they are detected the
//! same way 7-Zip does.
//!
//! <https://github.com/mcmilk/7-Zip/blob/HEAD/CPP/7zip/Archive/Nsis/NsisIn.cpp#L2425>

use tracing::debug;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, LE, TryFromBytes, U32};

use super::{
    Entry, NsisError, Variables,
    strings::{PredefinedVar, code::NsCode},
};

/// Opcodes in the layout used by [`Entry`].
mod opcode {
    pub const REGISTER_DLL: u32 = 44;
    pub const FILE_SEEK: u32 = 58;
    pub const WRITE_UNINSTALLER: u32 = 62;
    pub const SECTION_SET: u32 = 63;
    pub const GET_OS_INFO: u32 = 65;
    pub const RESERVED_OPCODE: u32 = 66;
    pub const FILE_WRITE_UTF16LE: u32 = 68;
    pub const FILE_READ_UTF16LE: u32 = 69;
    pub const LOG: u32 = 70;
    pub const FIND_PROCESS: u32 = 71;
    pub const GET_FONT_VERSION: u32 = 72;
    pub const GET_FONT_NAME: u32 = 73;
}

/// The maximum number of parameters used by each opcode in the layout used by [`Entry`].
///
/// <https://github.com/mcmilk/7-Zip/blob/HEAD/CPP/7zip/Archive/Nsis/NsisIn.cpp#L180>
const NUM_PARAMS: [u8; 74] = [
    0, 0, 1, 1, 0, 2, 6, 1, 0, 2, 2, 3, 3, 4, 4, 2, 4, 3, 2, 2, 6, 2, 6, 2, 2, 4, 5, 3, 6, 4, 4, 6,
    5, 6, 3, 3, 2, 4, 5, 4, 6, 3, 3, 4, 6, 6, 4, 1, 5, 4, 5, 6, 5, 5, 1, 4, 3, 4, 4, 1, 2, 3, 4, 5,
    4, 6, 2, 1, 4, 4, 2, 2, 2, 2,
];

/// An entry before its opcode has been translated.
#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct RawEntry {
    opcode: U32<LE>,
    params: [U32<LE>; 6],
}

impl RawEntry {
    /// Returns the number of parameters up to and including the last non-zero parameter.
    fn num_used_params(&self) -> usize {
        self.params
            .iter()
            .rposition(|&param| param != U32::ZERO)
            .map_or(0, |index| index + 1)
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum ParkVersion {
    #[default]
    Park1,
    /// Park 2.46.2 added `GetFontVersion`.
    Park2,
    /// Park 2.46.3 added `GetFontName` and is distributed with logging enabled.
    Park3,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ParkLayout {
    version: ParkVersion,
    log: bool,
    unicode: bool,
}

impl ParkLayout {
    /// Detects the Park opcode layout from the raw entries and strings blocks.
    ///
    /// <https://github.com/mcmilk/7-Zip/blob/HEAD/CPP/7zip/Archive/Nsis/NsisIn.cpp#L2523>
    pub fn detect(entries: &[RawEntry], strings_block: &[u8], unicode: bool) -> Self {
        let mut layout = Self {
            version: ParkVersion::Park1,
            log: false,
            unicode,
        };

        let version = layout.version_from_write_uninstaller(entries, strings_block);
        if let Some(version) = version {
            layout.version = version;
        }

        let mut bad_opcode = layout.find_bad_opcode(entries);

        if bad_opcode.is_none_or(|opcode| opcode < opcode::REGISTER_DLL) {
            return layout;
        }

        let is_bad_before_section_set = |opcode: Option<u32>| {
            opcode.is_some_and(|opcode| (1..opcode::SECTION_SET).contains(&opcode))
        };

        if version.is_none() && is_bad_before_section_set(bad_opcode) {
            layout.version = ParkVersion::Park3;
            layout.log = true;
            bad_opcode = layout.find_bad_opcode(entries);
            if is_bad_before_section_set(bad_opcode) {
                layout.version = ParkVersion::Park2;
                layout.log = false;
                bad_opcode = layout.find_bad_opcode(entries);
                if is_bad_before_section_set(bad_opcode) {
                    layout.version = ParkVersion::Park1;
                    bad_opcode = layout.find_bad_opcode(entries);
                }
            }
        }

        let is_bad_from_section_set =
            |opcode: Option<u32>| opcode.is_some_and(|opcode| opcode >= opcode::SECTION_SET);

        if is_bad_from_section_set(bad_opcode) {
            layout.log = !layout.log;
            if layout.log && is_bad_from_section_set(layout.find_bad_opcode(entries)) {
                layout.log = false;
            }
        }

        layout
    }

    /// Translates a raw Park opcode to the layout used by [`Entry`].
    ///
    /// <https://github.com/mcmilk/7-Zip/blob/HEAD/CPP/7zip/Archive/Nsis/NsisIn.cpp#L2425>
    pub fn translate(self, mut opcode: u32) -> u32 {
        if opcode < opcode::REGISTER_DLL {
            return opcode;
        }

        if self.version >= ParkVersion::Park2 {
            if opcode == opcode::REGISTER_DLL {
                return opcode::GET_FONT_VERSION;
            }
            opcode -= 1;
        }

        if self.version >= ParkVersion::Park3 {
            if opcode == opcode::REGISTER_DLL {
                return opcode::GET_FONT_NAME;
            }
            opcode -= 1;
        }

        if opcode >= opcode::FILE_SEEK {
            if self.unicode {
                if opcode == opcode::FILE_SEEK {
                    return opcode::FILE_WRITE_UTF16LE;
                } else if opcode == opcode::FILE_SEEK + 1 {
                    return opcode::FILE_READ_UTF16LE;
                }
                opcode -= 2;
            }

            if opcode >= opcode::SECTION_SET && self.log {
                return if opcode == opcode::SECTION_SET {
                    opcode::LOG
                } else {
                    opcode - 1
                };
            }

            if opcode == opcode::FILE_WRITE_UTF16LE {
                return opcode::FIND_PROCESS;
            }
        }

        opcode
    }

    /// Reads the entries, translating their opcodes to the layout used by [`Entry`].
    pub fn read_entries(self, entries: &[RawEntry]) -> Vec<Entry> {
        entries
            .iter()
            .map(|raw_entry| {
                let opcode = self.translate(raw_entry.opcode.get());
                let entry = RawEntry {
                    opcode: opcode.into(),
                    params: raw_entry.params,
                };
                Entry::try_read_from_bytes(entry.as_bytes()).unwrap_or_else(|_| {
                    debug!(opcode, "Entry has invalid parameters for its opcode");
                    Entry::Invalid
                })
            })
            .collect()
    }

    /// Returns the lowest translated opcode that is not used by Park or has more parameters than
    /// the opcode uses.
    ///
    /// <https://github.com/mcmilk/7-Zip/blob/HEAD/CPP/7zip/Archive/Nsis/NsisIn.cpp#L2468>
    fn find_bad_opcode(self, entries: &[RawEntry]) -> Option<u32> {
        let mut bad_opcode = None;

        for entry in entries {
            let opcode = self.translate(entry.opcode.get());

            let Some(&num_params) = NUM_PARAMS.get(opcode as usize) else {
                continue;
            };

            if bad_opcode.is_some_and(|bad_opcode| opcode >= bad_opcode) {
                continue;
            }

            let num_used_params = entry.num_used_params();

            // Park is based on NSIS 2, where these opcodes are only used by the compiler
            if matches!(opcode, opcode::GET_OS_INFO | opcode::RESERVED_OPCODE)
                || (opcode == opcode::FIND_PROCESS && num_used_params == 0)
                || usize::from(num_params) < num_used_params
            {
                bad_opcode = Some(opcode);
            }
        }

        bad_opcode
    }

    /// Detects the Park version from the position of `WriteUninstaller` entries, which are
    /// recognisable by their alternative path being `$INSTDIR\<name>`.
    ///
    /// Returns [`None`] if the version could not be determined.
    ///
    /// <https://github.com/mcmilk/7-Zip/blob/HEAD/CPP/7zip/Archive/Nsis/NsisIn.cpp#L2626>
    fn version_from_write_uninstaller(
        self,
        entries: &[RawEntry],
        strings_block: &[u8],
    ) -> Option<ParkVersion> {
        let strings = StringsBlock {
            data: strings_block,
            unicode: self.unicode,
        };

        let max_inserted_opcodes = if self.unicode { 4 } else { 2 };

        let mut mask = 0u32;

        for entry in entries {
            let Some(inserted_opcodes) = entry
                .opcode
                .get()
                .checked_sub(opcode::WRITE_UNINSTALLER)
                .filter(|&inserted| inserted <= max_inserted_opcodes)
            else {
                continue;
            };

            let [name, _, _, alternative_path, param_4, param_5] = entry.params.map(U32::get);

            if param_4 != 0 || param_5 != 0 || name <= 1 || alternative_path <= 1 {
                continue;
            }

            let (name, alternative_path) = (name as usize, alternative_path as usize);

            if !strings.is_string_start(name) || !strings.is_string_start(alternative_path) {
                continue;
            }

            if let Some(var_length) = strings.instdir_prefix_length(alternative_path)
                && strings.are_equal(alternative_path + var_length, name)
            {
                mask |= 1 << inserted_opcodes;
            }
        }

        match (mask, self.unicode) {
            (0b1, _) => Some(ParkVersion::Park1),
            (0b1000, true) | (0b10, false) => Some(ParkVersion::Park2),
            (0b1_0000, true) | (0b100, false) => Some(ParkVersion::Park3),
            _ => None,
        }
    }
}

/// Reads the raw entries from the entries block.
pub fn raw_entries(entries_block: &[u8]) -> Result<&[RawEntry], NsisError> {
    <[RawEntry]>::ref_from_bytes(entries_block).map_err(NsisError::from)
}

/// A strings block indexed by character position, as entry parameters are.
struct StringsBlock<'data> {
    data: &'data [u8],
    unicode: bool,
}

impl StringsBlock<'_> {
    const BACKSLASH: u16 = b'\\' as u16;

    const INSTDIR: usize = Variables::NUM_REGISTERS + PredefinedVar::InstDir as usize;

    fn char_at(&self, position: usize) -> Option<u16> {
        if self.unicode {
            let start = position.checked_mul(size_of::<u16>())?;
            let bytes = self.data.get(start..start + size_of::<u16>())?;
            Some(u16::from_le_bytes([bytes[0], bytes[1]]))
        } else {
            self.data.get(position).copied().map(u16::from)
        }
    }

    /// Returns `true` if a string starts at the position.
    fn is_string_start(&self, position: usize) -> bool {
        self.char_at(position).is_some()
            && (position == 0 || matches!(self.char_at(position - 1), Some(0 | Self::BACKSLASH)))
    }

    /// Returns the number of characters of the `$INSTDIR\` prefix if the string at the position
    /// starts with it.
    fn instdir_prefix_length(&self, position: usize) -> Option<usize> {
        let code = self.char_at(position)?;
        let code = if self.unicode {
            NsCode::try_from_park(code)
        } else {
            code.try_into().ok()
        };

        if !matches!(code, Some(NsCode::VarV2)) {
            return None;
        }

        let (var_index, length) = if self.unicode {
            let index = self.char_at(position + 1).filter(|&index| index != 0)?;
            (usize::from(index & 0x7FFF), 2)
        } else {
            let low = self.char_at(position + 1).filter(|&low| low != 0)?;
            let high = self.char_at(position + 2).filter(|&high| high != 0)?;
            (usize::from((low & 0x7F) | ((high & 0x7F) << 7)), 3)
        };

        (var_index == Self::INSTDIR && self.char_at(position + length)? == Self::BACKSLASH)
            .then_some(length + 1)
    }

    /// Returns `true` if the strings at the two positions are equal.
    fn are_equal(&self, mut first: usize, mut second: usize) -> bool {
        if first == second {
            return true;
        }

        loop {
            match (self.char_at(first), self.char_at(second)) {
                (Some(0), Some(0)) => return true,
                (Some(a), Some(b)) if a == b => {}
                _ => return false,
            }
            first += 1;
            second += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use zerocopy::{IntoBytes, TryFromBytes};

    use super::{Entry, ParkLayout, ParkVersion, RawEntry, opcode};

    const fn layout(version: ParkVersion, log: bool) -> ParkLayout {
        ParkLayout {
            version,
            log,
            unicode: true,
        }
    }

    fn raw_entry(opcode: u32, params: [u32; 6]) -> RawEntry {
        RawEntry {
            opcode: opcode.into(),
            params: params.map(Into::into),
        }
    }

    #[rstest]
    #[case(opcode::REGISTER_DLL, "RegisterDLL")]
    #[case(opcode::FILE_SEEK, "FileSeek")]
    #[case(opcode::WRITE_UNINSTALLER, "WriteUninstaller")]
    #[case(opcode::SECTION_SET, "SectionSet")]
    #[case(opcode::GET_OS_INFO, "GetOSInfo")]
    #[case(opcode::RESERVED_OPCODE, "ReservedOPCode")]
    #[case(opcode::FILE_WRITE_UTF16LE, "FileWriteUTF16LE")]
    #[case(opcode::FILE_READ_UTF16LE, "FileReadUTF16LE")]
    #[case(opcode::LOG, "Log")]
    #[case(opcode::FIND_PROCESS, "FindProcess")]
    #[case(opcode::GET_FONT_VERSION, "GetFontVersion")]
    #[case(opcode::GET_FONT_NAME, "GetFontName")]
    fn opcode_matches_entry(#[case] opcode: u32, #[case] name: &str) {
        let entry = Entry::try_read_from_bytes(raw_entry(opcode, [0; 6]).as_bytes()).unwrap();
        assert!(format!("{entry:?}").starts_with(name));
    }

    #[test]
    fn num_params_covers_every_opcode() {
        let opcode = super::NUM_PARAMS.len() as u32;
        assert!(Entry::try_read_from_bytes(raw_entry(opcode - 1, [0; 6]).as_bytes()).is_ok());
        assert!(Entry::try_read_from_bytes(raw_entry(opcode, [0; 6]).as_bytes()).is_err());
    }

    /// Opcodes before `RegisterDLL` are the same in every layout.
    #[rstest]
    fn opcodes_before_register_dll_are_unchanged(
        #[values(ParkVersion::Park1, ParkVersion::Park2, ParkVersion::Park3)] version: ParkVersion,
        #[values(false, true)] log: bool,
    ) {
        for raw in 0..opcode::REGISTER_DLL {
            assert_eq!(layout(version, log).translate(raw), raw);
        }
    }

    #[rstest]
    // Park 1 Unicode: FileWriteUTF16LE and FileReadUTF16LE are inserted before FileSeek
    #[case(layout(ParkVersion::Park1, false), 44, opcode::REGISTER_DLL)]
    #[case(layout(ParkVersion::Park1, false), 58, opcode::FILE_WRITE_UTF16LE)]
    #[case(layout(ParkVersion::Park1, false), 59, opcode::FILE_READ_UTF16LE)]
    #[case(layout(ParkVersion::Park1, false), 60, opcode::FILE_SEEK)]
    #[case(layout(ParkVersion::Park1, false), 64, opcode::WRITE_UNINSTALLER)]
    #[case(layout(ParkVersion::Park1, false), 65, opcode::SECTION_SET)]
    #[case(layout(ParkVersion::Park1, false), 70, opcode::FIND_PROCESS)]
    // Park 2 Unicode: GetFontVersion is inserted before RegisterDLL
    #[case(layout(ParkVersion::Park2, false), 44, opcode::GET_FONT_VERSION)]
    #[case(layout(ParkVersion::Park2, false), 45, opcode::REGISTER_DLL)]
    #[case(layout(ParkVersion::Park2, false), 59, opcode::FILE_WRITE_UTF16LE)]
    #[case(layout(ParkVersion::Park2, false), 61, opcode::FILE_SEEK)]
    #[case(layout(ParkVersion::Park2, false), 65, opcode::WRITE_UNINSTALLER)]
    #[case(layout(ParkVersion::Park2, false), 66, opcode::SECTION_SET)]
    // Park 3 Unicode with logging: GetFontName is inserted before RegisterDLL and Log before
    // SectionSet
    #[case(layout(ParkVersion::Park3, true), 44, opcode::GET_FONT_VERSION)]
    #[case(layout(ParkVersion::Park3, true), 45, opcode::GET_FONT_NAME)]
    #[case(layout(ParkVersion::Park3, true), 46, opcode::REGISTER_DLL)]
    #[case(layout(ParkVersion::Park3, true), 60, opcode::FILE_WRITE_UTF16LE)]
    #[case(layout(ParkVersion::Park3, true), 61, opcode::FILE_READ_UTF16LE)]
    #[case(layout(ParkVersion::Park3, true), 62, opcode::FILE_SEEK)]
    #[case(layout(ParkVersion::Park3, true), 66, opcode::WRITE_UNINSTALLER)]
    #[case(layout(ParkVersion::Park3, true), 67, opcode::LOG)]
    #[case(layout(ParkVersion::Park3, true), 68, opcode::SECTION_SET)]
    #[case(layout(ParkVersion::Park3, true), 69, opcode::SECTION_SET + 1)]
    fn translate(#[case] layout: ParkLayout, #[case] raw: u32, #[case] expected: u32) {
        assert_eq!(layout.translate(raw), expected);
    }

    #[test]
    fn translate_ansi() {
        let layout = ParkLayout {
            version: ParkVersion::Park1,
            log: false,
            unicode: false,
        };

        assert_eq!(layout.translate(58), opcode::FILE_SEEK);
        assert_eq!(layout.translate(62), opcode::WRITE_UNINSTALLER);
    }

    /// Builds a UTF-16 strings block with `$INSTDIR\uninst.exe` at position 2 and `uninst.exe` at
    /// the position returned.
    fn strings_block() -> (Vec<u8>, u32) {
        let mut chars = vec![0, 0, 0xE001, 0x8000 | 21, u16::from(b'\\')];
        let name_position = chars.len() as u32;
        chars.extend("uninst.exe".encode_utf16());
        chars.push(0);
        (chars.as_bytes().to_vec(), name_position)
    }

    #[rstest]
    #[case(ParkVersion::Park2, 65)]
    #[case(ParkVersion::Park3, 66)]
    fn detect_version_from_write_uninstaller(
        #[case] expected: ParkVersion,
        #[case] write_uninstaller: u32,
    ) {
        let (strings, name) = strings_block();
        let entries = [
            raw_entry(1, [0; 6]),
            raw_entry(write_uninstaller, [name, 0x1000, 0x2000, 2, 0, 0]),
        ];

        assert_eq!(
            ParkLayout::detect(&entries, &strings, true).version,
            expected
        );
    }

    #[test]
    fn detect_park_3_with_log_from_params() {
        // Park 3 Unicode entries with logging enabled. In the Park 1 layout, `WriteReg` (raw
        // opcode 53) would be `RegEnumKey`, which only has 5 parameters, and `LogText` (raw opcode
        // 67) and `SectionSet` (raw opcode 68) would be the compiler-only `GetLabelAddr` and
        // `GetFunctionAddr`.
        let entries = [
            raw_entry(53, [1, 2, 3, 4, 5, 6]),
            raw_entry(67, [0, 5, 0, 0, 0, 0]),
            raw_entry(68, [1, 2, 3, 4, 5, 0]),
        ];

        let detected = ParkLayout::detect(&entries, &[0, 0], true);
        assert_eq!(detected, layout(ParkVersion::Park3, true));
    }

    #[test]
    fn detect_park_1_without_bad_opcodes() {
        let entries = [raw_entry(2, [5, 0, 0, 0, 0, 0]), raw_entry(1, [0; 6])];

        assert_eq!(
            ParkLayout::detect(&entries, &[0, 0], true),
            layout(ParkVersion::Park1, false)
        );
    }

    #[test]
    fn read_entries_translates_opcodes() {
        let entries = [raw_entry(67, [0, 5, 0, 0, 0, 0]), raw_entry(0xFFFF, [0; 6])];

        let read = layout(ParkVersion::Park3, true).read_entries(&entries);

        assert!(matches!(read[0], Entry::Log { set, text } if set == 0 && text == 5));
        assert_eq!(read[1], Entry::Invalid);
    }
}
