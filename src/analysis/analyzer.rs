use std::{
    io::{Read, Seek},
    mem,
};

use camino::Utf8Path;
use color_eyre::eyre::Result;
use winget_types::{
    installer::{Architecture, Installer},
    locale::{Copyright, PackageName, Publisher},
    utils::ValidFileExtensions,
};

use super::{FontInfo, PeInfo};
use crate::analysis::{
    Installers,
    installers::{
        Exe, Font, Msi, Zip,
        font::FontAnalysis,
        msix_family::{Msix, bundle::MsixBundle, utils::is_signed},
    },
};

pub struct Analyzer<'reader, R: Read + Seek> {
    pub file_name: String,
    pub copyright: Option<Copyright>,
    pub package_name: Option<PackageName>,
    pub publisher: Option<Publisher>,
    #[allow(dead_code)]
    pub file_version: Option<String>,
    #[allow(dead_code)]
    pub product_version: Option<String>,
    pub font_version: Option<String>,
    pub font_info: Option<FontInfo>,
    pub pe_info: Option<PeInfo>,
    pub installers: Vec<Installer>,
    pub zip: Option<Zip<&'reader mut R>>,
}

impl<'reader, R: Read + Seek> Analyzer<'reader, R> {
    pub(crate) fn new(
        reader: &'reader mut R,
        file_name: &str,
        font_analysis: FontAnalysis,
    ) -> Result<Self> {
        let extension = ValidFileExtensions::from_path(Utf8Path::new(file_name))?;

        let installers = match extension {
            ValidFileExtensions::Msi => Msi::new(reader)?.installers(),
            // Windows cannot install an unsigned package as an MSIX, so WinGet manifests carry
            // those as a zip with a portable payload, which is what zip analysis produces.
            ValidFileExtensions::Msix | ValidFileExtensions::Appx if is_signed(&mut *reader)? => {
                reader.rewind()?;
                Msix::new(reader)?.installers()
            }
            ValidFileExtensions::Zip | ValidFileExtensions::Msix | ValidFileExtensions::Appx => {
                reader.rewind()?;
                let mut scoped_zip = Zip::new(reader, font_analysis)?;
                let installers = mem::take(&mut scoped_zip.installers);
                return Ok(Self {
                    installers,
                    zip: Some(scoped_zip),
                    ..Self::default()
                });
            }
            ValidFileExtensions::MsixBundle | ValidFileExtensions::AppxBundle => {
                MsixBundle::new(reader)?.installers()
            }
            ValidFileExtensions::Exe => {
                let mut exe = Exe::new(reader)?;
                let mut installers = exe.installers();
                override_x86_from_file_name(&mut installers, file_name);
                return Ok(Self {
                    installers,
                    copyright: exe
                        .legal_copyright
                        .take()
                        .and_then(|copyright| Copyright::new(copyright).ok()),
                    package_name: exe
                        .product_name
                        .take()
                        .and_then(|product_name| PackageName::new(product_name).ok()),
                    publisher: exe
                        .company_name
                        .take()
                        .and_then(|company_name| Publisher::new(company_name).ok()),
                    file_version: exe.file_version.take(),
                    product_version: exe.product_version.take(),
                    pe_info: exe.pe_info.take(),
                    ..Self::default()
                });
            }
            ValidFileExtensions::Fnt
            | ValidFileExtensions::Otc
            | ValidFileExtensions::Otf
            | ValidFileExtensions::Ttc
            | ValidFileExtensions::Ttf => {
                let font = Font::new(reader, file_name, font_analysis)?;
                let installers = font.installers();
                let (font_version, font_info) = match font_analysis {
                    FontAnalysis::Version => {
                        (font.info.and_then(FontInfo::into_font_version), None)
                    }
                    FontAnalysis::Full => (None, font.info),
                    FontAnalysis::None => (None, None),
                };
                return Ok(Self {
                    installers,
                    font_version,
                    font_info,
                    ..Self::default()
                });
            }
        };
        Ok(Self {
            installers,
            ..Self::default()
        })
    }

    /// Consumes the [`Analyzer`], returning the inner installers.
    pub fn into_installers(self) -> Vec<Installer> {
        self.installers
    }
}

/// Architecture names that can appear in an installer's file name, and the architecture that they
/// indicate.
///
/// Only 64-bit and ARM64 names are listed, because this table is used solely to correct an x86
/// architecture that came from a 32-bit installer stub. Longer names come first so that the longest
/// name matching at a given position wins.
const FILE_NAME_ARCHITECTURES: &[(&str, Architecture)] = &[
    ("winarm64", Architecture::Arm64),
    ("aarch64", Architecture::Arm64),
    ("arm64ec", Architecture::Arm64),
    ("x86_64", Architecture::X64),
    ("x86-64", Architecture::X64),
    ("win64a", Architecture::Arm64),
    ("64-bit", Architecture::X64),
    ("winx64", Architecture::X64),
    ("64bit", Architecture::X64),
    ("amd64", Architecture::X64),
    ("arm64", Architecture::Arm64),
    ("win64", Architecture::X64),
    ("ia64", Architecture::X64),
    ("x64", Architecture::X64),
];

/// Characters that may delimit an architecture name within a file name.
const DELIMITERS: [u8; 8] = [b',', b'.', b'_', b'-', b'(', b')', b'+', b' '];

/// Detects a 64-bit or ARM64 architecture from an installer's file name.
///
/// The rightmost delimited name wins, so `MyApp-win32-x64.exe` is x64 rather than being confused by
/// the `win32` in the middle.
///
/// This deliberately doesn't use [`Architecture::from_url`], which expects a full URL and both
/// misreads and panics on bare file names.
fn architecture_from_file_name(file_name: &str) -> Option<Architecture> {
    fn is_delimited_at(bytes: &[u8], start: usize, len: usize) -> bool {
        (start == 0
            || bytes
                .get(start - 1)
                .is_some_and(|byte| DELIMITERS.contains(byte)))
            && (start + len == bytes.len()
                || bytes
                    .get(start + len)
                    .is_some_and(|byte| DELIMITERS.contains(byte)))
    }

    let file_name = file_name.to_ascii_lowercase();
    let bytes = file_name.as_bytes();

    (0..bytes.len()).rev().find_map(|index| {
        let rest = file_name.get(index..)?;
        FILE_NAME_ARCHITECTURES
            .iter()
            .find(|(name, _)| rest.starts_with(*name) && is_delimited_at(bytes, index, name.len()))
            .map(|&(_, architecture)| architecture)
    })
}

/// Overrides the architecture of any x86 installer with the architecture named in the file name.
///
/// A 64-bit or ARM64 application is frequently shipped inside a 32-bit installer stub, in which
/// case the PE header only describes the stub. The file name is a better hint than the stub's
/// machine type when the two disagree, so it wins.
fn override_x86_from_file_name(installers: &mut [Installer], file_name: &str) {
    if !installers
        .iter()
        .any(|installer| installer.architecture.is_x86())
    {
        return;
    }

    let Some(architecture) = architecture_from_file_name(file_name) else {
        return;
    };

    for installer in installers
        .iter_mut()
        .filter(|installer| installer.architecture.is_x86())
    {
        installer.architecture = architecture;
    }
}

impl<R: Read + Seek> Default for Analyzer<'_, R> {
    fn default() -> Self {
        Self {
            file_name: String::default(),
            copyright: None,
            package_name: None,
            publisher: None,
            file_version: None,
            product_version: None,
            font_version: None,
            font_info: None,
            pe_info: None,
            installers: Vec::default(),
            zip: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use winget_types::installer::{Architecture, Installer};

    use super::override_x86_from_file_name;

    fn installer(architecture: Architecture) -> Installer {
        Installer {
            architecture,
            ..Installer::default()
        }
    }

    #[rstest]
    #[case("MyApp-arm64.exe", Architecture::Arm64)]
    #[case("MyApp_aarch64.exe", Architecture::Arm64)]
    #[case("MyApp-amd64.exe", Architecture::X64)]
    #[case("MyApp.x64.exe", Architecture::X64)]
    #[case("MyApp-win64.exe", Architecture::X64)]
    #[case("MyApp-x86_64.exe", Architecture::X64)]
    #[case("MyApp-arm64ec.exe", Architecture::Arm64)]
    // The rightmost architecture name wins
    #[case("MyApp-win32-x64.exe", Architecture::X64)]
    #[case("MyApp_x64_arm64.exe", Architecture::Arm64)]
    fn overrides_x86_with_file_name_architecture(
        #[case] file_name: &str,
        #[case] expected: Architecture,
    ) {
        let mut installers = vec![installer(Architecture::X86)];

        override_x86_from_file_name(&mut installers, file_name);

        assert_eq!(installers[0].architecture, expected);
    }

    #[rstest]
    #[case("MyApp.exe")]
    #[case("MyApp-x86.exe")]
    #[case("MyApp-win32.exe")]
    #[case("MyApp-neutral.exe")]
    // `x64` here is part of a longer word, so it isn't a delimited architecture name
    #[case("MyAppx64Bridge.exe")]
    fn keeps_x86_without_a_better_file_name_architecture(#[case] file_name: &str) {
        let mut installers = vec![installer(Architecture::X86)];

        override_x86_from_file_name(&mut installers, file_name);

        assert_eq!(installers[0].architecture, Architecture::X86);
    }

    #[test]
    fn does_not_override_a_non_x86_architecture() {
        let mut installers = vec![installer(Architecture::Arm64)];

        override_x86_from_file_name(&mut installers, "MyApp-x64.exe");

        assert_eq!(installers[0].architecture, Architecture::Arm64);
    }
}
