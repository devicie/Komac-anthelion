use std::{mem, num::NonZeroUsize, sync::Arc};

use color_eyre::eyre::{Report, eyre};
use futures_util::TryFutureExt;
use itertools::Itertools;
use napi::Either;
use tokio::try_join;
use winget_types::{
    PackageIdentifier, PackageVersion,
    installer::{InstallerType, MinimumOSVersion},
    locale::ReleaseNotes,
    url::ReleaseNotesUrl,
};

use super::{
    analyze_installer::{analyze_sources, normalize_installer_inputs, parse_installer_url},
    error::{AnthelionError, AnthelionResult, ErrorCode},
    types::{
        CreatedPullRequest, GeneratedManifest, ReplacementSelection, UpdatePackageRequest,
        UpdatePackageResult, UpdatedPackage, VersionSelection,
    },
    update_helpers::{fix_relative_paths, resolve_replace_version},
};
use crate::{
    download::Downloader,
    github::{
        GITHUB_HOST,
        client::GitHub,
        utils::{PackagePath, pull_request::pr_changes},
    },
    manifests::Url,
    match_installers::match_installers,
    traits::LocaleExt,
};

enum VersionSelector {
    Explicit(Box<PackageVersion>),
    ProductVersion,
    FileVersion,
    DisplayVersion,
}

fn parse_version_selector(
    selection: Either<String, VersionSelection>,
) -> AnthelionResult<VersionSelector> {
    let selection = match selection {
        Either::A(value) => VersionSelection {
            source: "explicit".to_owned(),
            value: Some(value),
        },
        Either::B(selection) => selection,
    };
    match selection.source.as_str() {
        "explicit" => {
            let value = selection
                .value
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty());
            let value = value.ok_or_else(|| {
                AnthelionError::invalid("version.value is required when version.source is explicit")
            })?;
            Ok(VersionSelector::Explicit(Box::new(value.parse().map_err(
                |error| AnthelionError::invalid(format!("Invalid package version: {error}")),
            )?)))
        }
        source @ ("display" | "product" | "file") => {
            if selection.value.is_some() {
                return Err(AnthelionError::invalid(
                    "version.value may only be set when version.source is explicit",
                ));
            }
            Ok(match source {
                "display" => VersionSelector::DisplayVersion,
                "product" => VersionSelector::ProductVersion,
                "file" => VersionSelector::FileVersion,
                _ => unreachable!(),
            })
        }
        source => Err(AnthelionError::invalid(format!(
            "Invalid version source {source:?}"
        ))),
    }
}

fn parse_replacement(
    replacement: Option<ReplacementSelection>,
) -> AnthelionResult<Option<PackageVersion>> {
    replacement
        .map(|replacement| match replacement.target.as_str() {
            "latest" => {
                if replacement.value.is_some() {
                    return Err(AnthelionError::invalid(
                        "replace.value may only be set when replace.target is version",
                    ));
                }
                "latest".parse().map_err(|error| {
                    AnthelionError::failure(
                        ErrorCode::UpdateFailed,
                        Report::from(error).wrap_err("Failed to create latest-version selector"),
                    )
                })
            }
            "version" => {
                let value = replacement
                    .value
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        AnthelionError::invalid(
                            "replace.value is required when replace.target is version",
                        )
                    })?;
                value.parse().map_err(|error| {
                    AnthelionError::invalid(format!("Invalid replacement version: {error}"))
                })
            }
            target => Err(AnthelionError::invalid(format!(
                "Invalid replacement target {target:?}"
            ))),
        })
        .transpose()
}

/// Update an existing package version in winget-pkgs.
///
/// # Errors
///
/// Returns `InvalidArg` when provided arguments are invalid (identifier, URLs, versions, or selectors).
/// Returns `GenericFailure` when downloading installers, analyzing content, loading manifests,
/// or creating the pull request fails.
pub async fn update_package(
    github: &GitHub,
    downloader: Arc<Downloader>,
    concurrency: NonZeroUsize,
    options: UpdatePackageRequest,
) -> AnthelionResult<UpdatePackageResult> {
    let submit = match options.mode.as_str() {
        "generate" => false,
        "submit" => true,
        mode => {
            return Err(AnthelionError::invalid(format!(
                "Invalid update mode {mode:?}"
            )));
        }
    };
    let package_identifier: PackageIdentifier = options
        .package_identifier
        .parse()
        .map_err(|e| AnthelionError::invalid(format!("Invalid package identifier: {e}")))?;

    let version_selector = parse_version_selector(options.version)?;

    let installers = normalize_installer_inputs(options.installers);

    let urls: Vec<Url> = installers
        .iter()
        .map(|source| parse_installer_url(&source.url))
        .collect::<AnthelionResult<_>>()?;

    if urls.is_empty() {
        return Err(AnthelionError::invalid("At least one URL is required"));
    }

    let release_notes_url: Option<ReleaseNotesUrl> = options
        .release_notes
        .as_ref()
        .and_then(|notes| notes.url.as_ref())
        .map(|url| url.parse())
        .transpose()
        .map_err(|e| AnthelionError::invalid(format!("Invalid release notes URL: {e}")))?;

    let release_notes: Option<ReleaseNotes> = options
        .release_notes
        .and_then(|notes| notes.text)
        .map(ReleaseNotes::new)
        .transpose()
        .map_err(|e| AnthelionError::invalid(format!("Invalid release notes: {e}")))?;

    let replace = parse_replacement(options.replace)?;

    let package_kind = match options.package_kind.as_deref() {
        None | Some("auto") => None,
        Some("standard") => Some(false),
        Some("font") => Some(true),
        Some(kind) => {
            return Err(AnthelionError::invalid(format!(
                "Invalid package kind {kind:?}"
            )));
        }
    };

    let versions = github
        .get_versions(&package_identifier)
    let (versions, font) = github
        .get_versions(&package_identifier, package_kind)
        .await
        .map_err(|e| {
            AnthelionError::failure(
                ErrorCode::UpdateFailed,
                Report::from(e).wrap_err("Failed to get versions"),
            )
        })?;

    let latest_version = versions.last().ok_or_else(|| {
        AnthelionError::failure(
            ErrorCode::UpdateFailed,
            eyre!("No versions found for package"),
        )
    })?;

    let (mut manifests, mut github_values, mut download_results) = try_join!(
        github
            .get_manifests(&package_identifier, latest_version, font)
            .map_err(|e| AnthelionError::failure(
                ErrorCode::UpdateFailed,
                Report::from(e).wrap_err("Failed to get manifests")
            )),
        async {
            if let Some(url) = urls.iter().find(|url| url.host_str() == Some(GITHUB_HOST)) {
                github
                    .get_all_values_from_url(url.clone().into_inner())
                    .await
                    .transpose()
                    .map_err(|e| {
                        AnthelionError::failure(
                            ErrorCode::UpdateFailed,
                            Report::from(e).wrap_err("Failed to get GitHub values"),
                        )
                    })
            } else {
                Ok(None)
            }
        },
        analyze_sources(downloader, concurrency, installers,),
    )?;

    let installer_results = download_results
        .iter_mut()
        .flat_map(|analysis| mem::take(&mut analysis.installers))
        .collect::<Vec<_>>();

    let product_version = download_results
        .iter()
        .filter_map(|analysis| analysis.product_version.as_deref())
        .map(str::trim)
        .find(|value| !value.is_empty());
    let file_version = download_results
        .iter()
        .filter_map(|analysis| analysis.file_version.as_deref())
        .map(str::trim)
        .find(|value| !value.is_empty());
    let display_version = installer_results
        .iter()
        .flat_map(|installer| installer.apps_and_features_entries.iter())
        .filter_map(|entry| {
            entry
                .display_version()
                .map(std::string::ToString::to_string)
        })
        .find(|value| !value.trim().is_empty());

    let package_version: PackageVersion = match version_selector {
        VersionSelector::Explicit(package_version) => *package_version,
        VersionSelector::ProductVersion => product_version
            .ok_or_else(|| {
                AnthelionError::invalid(
                    "version.source is product, but installer analysis found no ProductVersion",
                )
            })?
            .parse()
            .map_err(|e| AnthelionError::invalid(format!("Invalid ProductVersion: {e}")))?,
        VersionSelector::FileVersion => file_version
            .ok_or_else(|| {
                AnthelionError::invalid(
                    "version.source is file, but installer analysis found no FileVersion",
                )
            })?
            .parse()
            .map_err(|e| AnthelionError::invalid(format!("Invalid FileVersion: {e}")))?,
        VersionSelector::DisplayVersion => display_version
            .ok_or_else(|| {
                AnthelionError::invalid(
                    "version.source is display, but installer analysis found no DisplayVersion",
                )
            })?
            .parse()
            .map_err(|e| AnthelionError::invalid(format!("Invalid DisplayVersion: {e}")))?,
    };

    let replace_version = resolve_replace_version(
        replace.as_ref(),
        &versions,
        latest_version,
        &package_version,
    )
    .map_err(AnthelionError::invalid)?;

    let possible_installer_files = download_results
        .into_iter()
        .map(|analysis| (analysis.url, analysis.possible_installer_files))
        .collect::<std::collections::HashMap<_, _>>();

    let previous_installers = mem::take(&mut manifests.installer.installers)
        .into_iter()
        .map(|mut installer| {
            if manifests.installer.r#type.is_some() {
                installer.r#type = manifests.installer.r#type;
            }
            if manifests.installer.nested_installer_type.is_some() {
                installer.nested_installer_type = manifests.installer.nested_installer_type;
            }
            if manifests.installer.scope.is_some() {
                installer.scope = manifests.installer.scope;
            }
            installer
        })
        .collect::<Vec<_>>();

    let duplicate_urls = previous_installers
        .iter()
        .map(|installer| installer.url.clone())
        .duplicates()
        .collect::<Vec<_>>();

    manifests.default_locale.package_version = package_version.clone();
    let matched_installers = match_installers(&previous_installers, &installer_results);
    let mut installers = matched_installers
        .into_iter()
        .map(|(previous_installer, new_installer)| {
            let possible_installer_files = possible_installer_files
                .get(&new_installer.url)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let installer_type = match previous_installer.r#type {
                Some(InstallerType::Portable) => previous_installer.r#type,
                _ => match new_installer.r#type {
                    Some(InstallerType::Portable) => previous_installer.r#type,
                    _ => new_installer.r#type,
                },
            };

            let previous_nested_files = previous_installer.nested_installer_files.clone();
            let previous_url = previous_installer.url.clone();
            let previous_architecture = previous_installer.architecture;

            let mut installer = new_installer.clone().merge_with(previous_installer);
            installer.r#type = installer_type;
            installer.url.clone_from(&new_installer.url);

            let nested_files_to_fix = [
                &previous_nested_files,
                &manifests.installer.nested_installer_files,
                &installer.nested_installer_files,
            ]
            .into_iter()
            .find(|files| !files.is_empty())
            .cloned();

            if let Some(nested_files) = nested_files_to_fix {
                installer.nested_installer_files =
                    fix_relative_paths(nested_files, possible_installer_files);
            }

            if duplicate_urls.contains(&previous_url) {
                installer.architecture = previous_architecture;
            }

            for entry in &mut installer.apps_and_features_entries {
                entry.deduplicate(&manifests.default_locale);
            }
            installer
        })
        .collect::<Vec<_>>();

    if installers
        .iter()
        .flat_map(|installer| &installer.locale)
        .all_equal()
    {
        for installer in &mut installers {
            installer.locale = None;
        }
    }

    manifests.installer.locale = None;

    manifests.installer.package_version = package_version.clone();
    manifests.installer.minimum_os_version = manifests
        .installer
        .minimum_os_version
        .filter(|minimum_os_version| *minimum_os_version != MinimumOSVersion::new(10, 0, 0, 0));
    manifests.installer.installers = installers;
    manifests.installer.optimize();

    manifests.default_locale.update(
        &package_version,
        &mut github_values,
        release_notes_url.as_ref(),
    );

    if let Some(release_notes) = release_notes {
        manifests.default_locale.release_notes = Some(release_notes);
    }

    manifests.locales.iter_mut().for_each(|locale| {
        locale.update(&package_version, &mut github_values, None);
    });

    manifests.version.update(&package_version);

    let package_path = PackagePath::new(&package_identifier, Some(&package_version), None);
    let changes = pr_changes()
        .package_identifier(&package_identifier)
        .manifests(&manifests)
        .package_path(&package_path)
        .create()
        .map_err(|e| {
            AnthelionError::failure(
                ErrorCode::UpdateFailed,
                e.wrap_err("Failed to create PR changes"),
            )
        })?;

    if !submit {
        return Ok(UpdatePackageResult {
            package: UpdatedPackage {
                identifier: package_identifier.to_string(),
                version: package_version.to_string(),
            },
            manifests: changes
                .into_iter()
                .map(|(path, yaml)| GeneratedManifest { path, yaml })
                .collect(),
            pull_request: None,
        });
    }

    let pull_request_url = github
        .add_version()
        .identifier(&package_identifier)
        .version(&package_version)
        .versions(&versions)
        .changes(changes.clone())
        .maybe_replace_version(replace_version)
        .issue_resolves(&[])
        .send()
        .await
        .map_err(|e| {
            AnthelionError::failure(
                ErrorCode::UpdateFailed,
                Report::from(e).wrap_err("Failed to create pull request"),
            )
        })?;

    Ok(UpdatePackageResult {
        package: UpdatedPackage {
            identifier: package_identifier.to_string(),
            version: package_version.to_string(),
        },
        manifests: changes
            .into_iter()
            .map(|(path, yaml)| GeneratedManifest { path, yaml })
            .collect(),
        pull_request: Some(CreatedPullRequest {
            url: pull_request_url.url().to_string(),
            diff_url: pull_request_url.diff_view_url().to_string(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use napi::Either;

    use super::{VersionSelector, parse_replacement, parse_version_selector};
    use crate::anthelion::types::{ReplacementSelection, VersionSelection};

    #[test]
    fn version_selection_requires_only_the_relevant_value() {
        assert!(matches!(
            parse_version_selector(Either::B(VersionSelection {
                source: "explicit".to_owned(),
                value: Some("1.2.3".to_owned()),
            }))
            .unwrap(),
            VersionSelector::Explicit(_)
        ));
        assert!(
            parse_version_selector(Either::B(VersionSelection {
                source: "product".to_owned(),
                value: Some("1.2.3".to_owned()),
            }))
            .is_err()
        );
    }

    #[test]
    fn latest_replacement_has_no_magic_string_in_the_public_api() {
        let replacement = parse_replacement(Some(ReplacementSelection {
            target: "latest".to_owned(),
            value: None,
        }))
        .unwrap()
        .unwrap();

        assert!(replacement.is_latest());
    }
}
