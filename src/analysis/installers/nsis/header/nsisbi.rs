//! Support for installers built with [nsisbi], a fork of NSIS for installers larger than 2 GB.
//!
//! Since 7405-1, nsisbi compresses data with a multithreaded wrapper that splits the input into
//! independently compressed blocks. Each block is prefixed with its compressed size as a 3-byte
//! little-endian integer, and the stream is terminated by a block with a size of 0.
//!
//! [nsisbi]: https://sourceforge.net/projects/nsisbi/

use std::io::{self, Cursor, Read};

use flate2::read::DeflateDecoder;
use lzma_rust2::LzmaReader;
use zerocopy::FromBytes;

use super::{Compression, is_bzip2, nsis_bzip2};
use crate::analysis::installers::utils::LzmaStreamHeader;

const BLOCK_HEADER_SIZE: usize = 3;

/// The largest decompressed block size used by any nsisbi version. The block size was 2 MiB for
/// all codecs before 3.12.1, which then made it codec-specific, with LZMA blocks being 4 MiB.
const MAX_BLOCK_DATA_SIZE: usize = 1 << 22;

pub struct Decoder<R> {
    inner: R,
    compression: Option<Compression>,
    block: Cursor<Vec<u8>>,
    finished: bool,
}

impl<R: Read> Decoder<R> {
    pub const fn new(reader: R) -> Self {
        Self {
            inner: reader,
            compression: None,
            block: Cursor::new(Vec::new()),
            finished: false,
        }
    }

    /// Returns the compression of the blocks, which is detected from the first block.
    pub const fn compression(&self) -> Option<Compression> {
        self.compression
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Reads and decompresses the next block, returning `false` if the end of the stream was
    /// reached.
    fn next_block(&mut self) -> io::Result<bool> {
        let mut size = [0; size_of::<u32>()];
        self.inner.read_exact(&mut size[..BLOCK_HEADER_SIZE])?;
        let size = u32::from_le_bytes(size) as usize;

        if size == 0 {
            return Ok(false);
        }

        let mut compressed = vec![0; size];
        self.inner.read_exact(&mut compressed)?;

        let compression = *self.compression.get_or_insert_with(|| {
            // The dictionary size is slightly larger than the block size, so it doesn't have the
            // zero bytes that `is_lzma` checks for. LZMA data always starts with a zero byte.
            if compressed.first() == Some(&0x5D) && compressed.get(5) == Some(&0) {
                Compression::Lzma(false)
            } else if is_bzip2(&compressed) {
                Compression::BZip2
            } else {
                Compression::Zlib
            }
        });

        let mut decompressed = Vec::new();
        match compression {
            Compression::Lzma(_) => {
                let (header, data) = LzmaStreamHeader::read_from_prefix(&compressed)
                    .map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))?;
                LzmaReader::new_with_props(
                    data,
                    u64::MAX,
                    header.props(),
                    header.dictionary_size(),
                    None,
                )?
                .take(MAX_BLOCK_DATA_SIZE as u64)
                .read_to_end(&mut decompressed)?;
            }
            Compression::BZip2 => {
                decompressed =
                    nsis_bzip2::decompress(&compressed, MAX_BLOCK_DATA_SIZE).map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
            }
            Compression::Zlib | Compression::Lzma2 | Compression::None => {
                DeflateDecoder::new(compressed.as_slice())
                    .take(MAX_BLOCK_DATA_SIZE as u64)
                    .read_to_end(&mut decompressed)?;
            }
        }

        self.block = Cursor::new(decompressed);
        Ok(true)
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let read = self.block.read(buf)?;
            if read != 0 || buf.is_empty() || self.finished {
                return Ok(read);
            }

            if !self.next_block()? {
                self.finished = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use flate2::{Compression as Level, write::DeflateEncoder};

    use super::{Compression, Decoder};

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Level::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn block(compressed: &[u8]) -> Vec<u8> {
        let mut block = u32::try_from(compressed.len()).unwrap().to_le_bytes()[..3].to_vec();
        block.extend_from_slice(compressed);
        block
    }

    #[test]
    fn multiple_deflate_blocks() {
        let mut stream = block(&deflate(b"Hello, "));
        stream.extend(block(&deflate(b"world!")));
        stream.extend([0, 0, 0]);
        stream.extend(b"trailing");

        let mut decoder = Decoder::new(stream.as_slice());
        let mut output = String::new();
        decoder.read_to_string(&mut output).unwrap();

        assert_eq!(output, "Hello, world!");
        assert_eq!(decoder.compression(), Some(Compression::Zlib));
        assert_eq!(decoder.into_inner(), b"trailing");
    }
}
