mod rate_limit;
mod submit_option;

use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::{
    Result,
    eyre::{bail, ensure},
};
use winget_types::installer::{InstallerManifest, InstallerType, NestedInstallerType};

use crate::traits::InstallerManifestExt;

pub use rate_limit::RateLimit;
pub use submit_option::SubmitOption;

pub const SPINNER_TICK_RATE: Duration = Duration::from_millis(50);

pub const SPINNER_SLOW_TICK_RATE: Duration = Duration::from_millis(100);

pub fn check_package_type(manifest: &InstallerManifest) -> Result<bool> {
    let (mut has_font, mut has_installer) = (false, false);

    for installer in manifest.inherit_manifest_properties() {
        if installer.r#type == Some(InstallerType::Font)
            || installer.nested_installer_type == Some(NestedInstallerType::Font)
        {
            has_font = true;
        } else {
            has_installer = true;
        }

        if has_font && has_installer {
            bail!("Application and font installers cannot be mixed in the same manifest");
        }
    }

    Ok(has_font)
}

/// Parses a CLI argument into a [`Utf8PathBuf`], erroring if it isn't an existing file.
pub fn is_valid_file(path: &str) -> Result<Utf8PathBuf> {
    let path = Utf8Path::new(path);
    ensure!(path.exists(), "{path} does not exist");
    ensure!(path.is_file(), "{path} is not a file");
    Ok(path.to_path_buf())
}
