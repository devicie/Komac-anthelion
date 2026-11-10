mod section_header;

use std::{io, slice, vec};

pub use section_header::SectionHeader;
use zerocopy::{FromZeros, IntoBytes};

use super::CoffHeader;

#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SectionTable(Vec<SectionHeader>);

impl SectionTable {
    #[inline]
    pub fn sections(&self) -> &[SectionHeader] {
        &self.0
    }

    pub fn read_from<R>(mut src: R, coff_header: CoffHeader) -> io::Result<Self>
    where
        R: io::Read,
    {
        let mut sections =
            vec![SectionHeader::new_zeroed(); coff_header.number_of_sections().into()];

        for section in &mut sections {
            src.read_exact(section.as_mut_bytes())?;
        }

        Ok(Self(sections))
    }

    /// Converts a virtual address (RVA) to a file offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the address was not found in any section.
    pub fn to_file_offset(&self, address: u32) -> io::Result<u32> {
        for section in self {
            let start = section.virtual_address();
            let end = start.saturating_add(section.mapped_size());

            if (start..end).contains(&address) {
                return Ok(address + section.pointer_to_raw_data() - start);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Address {address:#X} not found in any section"),
        ))
    }
}

impl<'table> IntoIterator for &'table SectionTable {
    type Item = &'table SectionHeader;

    type IntoIter = slice::Iter<'table, SectionHeader>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::FromBytes;

    use super::{SectionHeader, SectionTable};

    fn section(
        virtual_size: u32,
        virtual_address: u32,
        raw_size: u32,
        raw_pointer: u32,
    ) -> SectionHeader {
        let mut bytes = [0; size_of::<SectionHeader>()];
        bytes[8..12].copy_from_slice(&virtual_size.to_le_bytes());
        bytes[12..16].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[16..20].copy_from_slice(&raw_size.to_le_bytes());
        bytes[20..24].copy_from_slice(&raw_pointer.to_le_bytes());
        SectionHeader::read_from_bytes(&bytes).unwrap()
    }

    #[test]
    fn converts_address_in_section() {
        let table = SectionTable(vec![section(0x7330, 0x1000, 0x7400, 0x400)]);

        assert_eq!(table.to_file_offset(0x1010).unwrap(), 0x410);
        assert!(table.to_file_offset(0x9000).is_err());
    }

    /// Old linkers, such as Watcom's, can leave a section's virtual size as zero.
    #[test]
    fn converts_address_in_section_without_virtual_size() {
        let table = SectionTable(vec![
            section(0, 0x1D000, 0x800, 0x9800),
            section(0, 0x1E000, 0x5400, 0xA000),
        ]);

        assert_eq!(table.to_file_offset(0x1E000).unwrap(), 0xA000);
        assert_eq!(table.to_file_offset(0x1E010).unwrap(), 0xA010);
    }
}
