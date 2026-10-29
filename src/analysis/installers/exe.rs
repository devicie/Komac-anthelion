use std::io::{Read, Seek};

use color_eyre::Result;
use inno::{Inno, InnoInner, error::InnoError};
use winget_types::installer::{Installer, InstallerType};

use super::{
    super::Installers, AdvancedInstaller, Burn, IExpress, InstallAware, InstallShield, Nsis, QtIfw,
    SevenZipSfx, SfxCab, Squirrel,
};
use crate::{
    analysis::{
        PeInfo,
        installers::{
            advanced::AdvancedInstallerError,
            burn::BurnError,
            iexpress::IExpressError,
            installaware::InstallAwareError,
            installshield::InstallShieldError,
            nsis::NsisError,
            pe::{PE, VSVersionInfo},
            qt_ifw::QtIfwError,
            sevenzip_sfx::SevenZipSfxError,
            sfxcab::{SfxCabError, setup_chainer_switches},
            squirrel::SquirrelError,
        },
    },
    traits::IntoWingetArchitecture,
};

const ORIGINAL_FILENAME: &str = "OriginalFilename";
const FILE_DESCRIPTION: &str = "FileDescription";
const BASIC_INSTALLER_KEYWORDS: [&str; 5] =
    ["installer", "setup", "bootstrapper", "7zs.sfx", "7zsd.sfx"];

/// The original file name of the self-extractor used by the .NET Framework 4.5 and later setups,
/// which runs the setup chainer.
const BOX_STUB: &str = "BoxStub.exe";

pub struct Exe {
    r#type: ExeType,
    pub legal_copyright: Option<String>,
    pub product_name: Option<String>,
    pub company_name: Option<String>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub pe_info: Option<PeInfo>,
}

pub enum ExeType {
    AdvancedInstaller(AdvancedInstaller),
    Burn(Box<Burn>),
    IExpress(Box<IExpress>),
    Inno(Box<InnoInner>),
    InstallAware(InstallAware),
    InstallShield(Box<InstallShield>),
    Nsis(Nsis),
    QtIfw(Box<QtIfw>),
    SevenZipSfx(Box<SevenZipSfx>),
    SfxCab(Box<SfxCab>),
    Squirrel(Squirrel),
    Generic(Box<Installer>),
}

impl Exe {
    pub fn new<R: Read + Seek>(mut reader: R) -> Result<Self> {
        let pe = PE::read_from(&mut reader)?;

        let vs_version_info_bytes = pe.vs_version_info(&mut reader).ok();
        let vs_version_info = vs_version_info_bytes
            .as_deref()
            .and_then(|version_info_bytes| VSVersionInfo::read_from(version_info_bytes).ok());
        let pe_info = vs_version_info.as_ref().map(PeInfo::from_version_info);
        let mut string_table = vs_version_info.as_ref().map(VSVersionInfo::string_table);
        let legal_copyright = string_table
            .as_mut()
            .and_then(|table| table.swap_remove("LegalCopyright"))
            .map(str::to_owned);
        let product_name = string_table
            .as_mut()
            .and_then(|table| table.swap_remove("ProductName"))
            .map(str::to_owned);
        let company_name = string_table
            .as_mut()
            .and_then(|table| table.swap_remove("CompanyName"))
            .map(str::to_owned);
        let file_version = pe_info
            .as_ref()
            .and_then(PeInfo::file_version)
            .map(str::to_owned);
        let product_version = pe_info
            .as_ref()
            .and_then(PeInfo::product_version)
            .map(str::to_owned);

        match AdvancedInstaller::new(&mut reader) {
            Ok(advanced) => {
                return Ok(Self {
                    r#type: ExeType::AdvancedInstaller(advanced),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(AdvancedInstallerError::NotAdvancedInstallerFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Burn::new(&mut reader, &pe) {
            Ok(burn) => {
                return Ok(Self {
                    r#type: ExeType::Burn(Box::new(burn)),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(BurnError::NotBurnFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Inno::new(&mut reader) {
            Ok(inno) => {
                return Ok(Self {
                    r#type: ExeType::Inno(Box::new(inno.inner)),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(InnoError::NotInnoFile) => {}
            Err(error) => return Err(error.into()),
        }

        match InstallAware::new(&mut reader, &pe) {
            Ok(installaware) => {
                return Ok(Self {
                    r#type: ExeType::InstallAware(installaware),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(InstallAwareError::NotInstallAwareFile) => {}
            Err(error) => return Err(error.into()),
        }

        match SevenZipSfx::new(&mut reader, &pe) {
            Ok(sevenzip_sfx) => {
                return Ok(Self {
                    r#type: ExeType::SevenZipSfx(Box::new(sevenzip_sfx)),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(SevenZipSfxError::NotSevenZipSfxFile) => {}
            Err(error) => return Err(error.into()),
        }

        match InstallShield::new(&mut reader, &pe) {
            Ok(installshield) => {
                return Ok(Self {
                    r#type: ExeType::InstallShield(Box::new(installshield)),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(InstallShieldError::NotInstallShieldFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Nsis::new(&mut reader, &pe) {
            Ok(nsis) => {
                return Ok(Self {
                    r#type: ExeType::Nsis(nsis),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(NsisError::NotNsisFile) => {}
            Err(error) => return Err(error.into()),
        }

        match QtIfw::new(&mut reader, &pe) {
            Ok(qt_ifw) => {
                return Ok(Self {
                    r#type: ExeType::QtIfw(Box::new(qt_ifw)),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(QtIfwError::NotQtIfwFile) => {}
            Err(error) => return Err(error.into()),
        }

        match SfxCab::new(&mut reader, &pe) {
            Ok(sfxcab) => {
                return Ok(Self {
                    r#type: ExeType::SfxCab(Box::new(sfxcab)),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(SfxCabError::NotSfxCabFile) => {}
            Err(error) => return Err(error.into()),
        }

        match IExpress::new(&mut reader, &pe) {
            Ok(iexpress) => {
                return Ok(Self {
                    r#type: ExeType::IExpress(Box::new(iexpress)),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(IExpressError::NotIExpressFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Squirrel::new(&mut reader, &pe) {
            Ok(squirrel) => {
                return Ok(Self {
                    r#type: ExeType::Squirrel(squirrel),
                    legal_copyright,
                    product_name,
                    company_name,
                    file_version,
                    product_version,
                    pe_info,
                });
            }
            Err(SquirrelError::NotSquirrelFile) => {}
            Err(error) => return Err(error.into()),
        }

        if is_box_stub(&mut reader, &pe) {
            return Ok(Self {
                r#type: ExeType::Generic(Box::new(Installer {
                    architecture: pe.winget_architecture(),
                    r#type: Some(InstallerType::Exe),
                    switches: setup_chainer_switches(),
                    ..Installer::default()
                })),
                legal_copyright,
                product_name,
                company_name,
                file_version,
                product_version,
                pe_info,
            });
        }

        Ok(Self {
            r#type: ExeType::Generic(Box::new(Installer {
                architecture: pe.winget_architecture(),
                r#type: if string_table.is_some_and(|mut table| {
                    let original_filename = table.swap_remove(ORIGINAL_FILENAME);
                    let file_description = table.swap_remove(FILE_DESCRIPTION);

                    is_installer_name(original_filename, file_description)
                }) {
                    Some(InstallerType::Exe)
                } else {
                    Some(InstallerType::Portable)
                },
                ..Installer::default()
            })),
            legal_copyright,
            product_name,
            company_name,
            file_version,
            product_version,
            pe_info,
        })
    }
}

impl Exe {
    /// Returns `true` if the installer framework wasn't recognised, so the installer type is a
    /// guess and there are no installer switches.
    #[inline]
    pub fn is_unrecognised(&self) -> bool {
        matches!(&self.r#type, ExeType::Generic(installer) if installer.switches.is_empty())
    }
}

/// Returns `true` if the original file name or file description suggests that the executable is
/// an installer.
fn is_installer_name(original_filename: Option<&str>, file_description: Option<&str>) -> bool {
    let contains_keyword = |value: &str| {
        let value = value.to_ascii_lowercase();
        BASIC_INSTALLER_KEYWORDS
            .iter()
            .any(|keyword| value.contains(keyword))
    };

    original_filename.is_some_and(|filename| {
        contains_keyword(filename)
            || filename
                .rsplit_once('.')
                .map_or(filename, |(stem, _extension)| stem)
                .to_ascii_lowercase()
                .ends_with("install")
    }) || file_description.is_some_and(contains_keyword)
}

/// Returns `true` if any version info of the executable is that of .NET's Box Stub.
fn is_box_stub<R: Read + Seek>(reader: R, pe: &PE) -> bool {
    pe.vs_version_infos(reader).is_ok_and(|version_infos| {
        version_infos.iter().any(|version_info| {
            VSVersionInfo::read_from(version_info).is_ok_and(|version_info| {
                version_info.string_entries().any(|(key, value)| {
                    key == ORIGINAL_FILENAME && value.trim().eq_ignore_ascii_case(BOX_STUB)
                })
            })
        })
    })
}

impl Installers for Exe {
    fn installers(&self) -> Vec<Installer> {
        match &self.r#type {
            ExeType::AdvancedInstaller(advanced) => advanced.installers(),
            ExeType::Burn(burn) => burn.installers(),
            ExeType::IExpress(iexpress) => iexpress.installers(),
            ExeType::Inno(inno) => inno.installers(),
            ExeType::InstallAware(installaware) => installaware.installers(),
            ExeType::InstallShield(installshield) => installshield.installers(),
            ExeType::Nsis(nsis) => nsis.installers(),
            ExeType::QtIfw(qt_ifw) => qt_ifw.installers(),
            ExeType::SevenZipSfx(sevenzip_sfx) => sevenzip_sfx.installers(),
            ExeType::SfxCab(sfxcab) => sfxcab.installers(),
            ExeType::Squirrel(squirrel) => squirrel.installers(),
            ExeType::Generic(installer) => vec![*installer.clone()],
        }
    }
}
