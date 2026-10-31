#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Compression {
    Lzma(bool),
    /// Raw LZMA2, prefixed with its dictionary size, as used by some custom NSIS builds.
    Lzma2,
    BZip2,
    Zlib,
    None,
}
