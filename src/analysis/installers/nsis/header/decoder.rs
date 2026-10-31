use std::io::{Read, Result, Seek};

use flate2::read::ZlibDecoder;
use lzma_rust2::{Lzma2Reader, LzmaReader};

use super::{LzmaStreamHeader, nsis_bzip2, nsisbi};

pub enum Decoder<R: Read + Seek> {
    Lzma(Box<LzmaReader<R>>),
    Lzma2(Box<Lzma2Reader<R>>),
    NsisBZip2(nsis_bzip2::Decoder<R>),
    NsisBi(nsisbi::Decoder<R>),
    Zlib(ZlibDecoder<R>),
    None(R),
}

impl<R: Read + Seek> Decoder<R> {
    /// Creates a new LZMA1 decoder from a reader and an [`LzmaStreamHeader`].
    pub fn new_lzma1(reader: R, header: LzmaStreamHeader) -> lzma_rust2::Result<Self> {
        LzmaReader::new_with_props(
            reader,
            u64::MAX,
            header.props(),
            header.dictionary_size(),
            None,
        )
        .map(|reader| Self::Lzma(Box::new(reader)))
    }

    /// Creates a new LZMA2 decoder from a reader and the dictionary size property used by xz.
    pub fn new_lzma2(reader: R, dictionary_size: u8) -> Self {
        // https://github.com/tukaani-project/xz/blob/v5.8.1/src/liblzma/lzma/lzma2_decoder.c#L291
        let dictionary_size = (2 | u32::from(dictionary_size & 1))
            .checked_shl(u32::from(dictionary_size / 2) + 11)
            .unwrap_or(u32::MAX);
        Self::Lzma2(Box::new(Lzma2Reader::new(reader, dictionary_size, None)))
    }
}

impl<R: Read + Seek> Decoder<R> {
    pub fn into_inner(self) -> R {
        match self {
            Self::Lzma(reader) => reader.into_inner(),
            Self::Lzma2(reader) => reader.into_inner(),
            Self::NsisBZip2(reader) => reader.into_inner(),
            Self::NsisBi(reader) => reader.into_inner(),
            Self::Zlib(reader) => reader.into_inner(),
            Self::None(reader) => reader,
        }
    }
}

impl<R: Read + Seek> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Lzma(reader) => reader.read(buf),
            Self::Lzma2(reader) => reader.read(buf),
            Self::NsisBZip2(reader) => reader.read(buf),
            Self::NsisBi(reader) => reader.read(buf),
            Self::Zlib(reader) => reader.read(buf),
            Self::None(reader) => reader.read(buf),
        }
    }
}
