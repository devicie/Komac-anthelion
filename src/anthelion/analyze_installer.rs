use std::{num::NonZeroUsize, sync::Arc};

use camino::Utf8PathBuf;
use color_eyre::eyre::{Report, eyre};
use futures_util::{StreamExt, TryStreamExt, stream};
use indexmap::IndexMap;
use napi::Either;
use winget_types::{Sha256String, installer::Installer, url::DecodedUrl};

use super::error::{AnthelionError, AnthelionResult, ErrorCode};
use super::types::{
    AnalyzedArtifact, AnalyzedInstaller, AppsAndFeaturesEntry, DetectedVersions, InstallerSource,
};
use crate::{
    analysis::Analyzer,
    download::{DownloadedFile, Downloader},
    manifests::Url,
};

#[derive(Clone)]
pub struct ArtifactAnalysis {
    pub url: DecodedUrl,
    pub sha256: Sha256String,
    pub release_date: Option<chrono::NaiveDate>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub installers: Vec<Installer>,
    pub possible_installer_files: Vec<Utf8PathBuf>,
}

pub fn normalize_installer_inputs(
    inputs: Vec<Either<String, InstallerSource>>,
) -> Vec<InstallerSource> {
    inputs
        .into_iter()
        .map(|input| match input {
            Either::A(url) => InstallerSource {
                url,
                architecture: None,
                nested_installer_matches: None,
            },
            Either::B(source) => source,
        })
        .collect()
}

pub(crate) fn parse_installer_url(input: &str) -> AnthelionResult<Url> {
    let url = input.trim();
    if url.is_empty() {
        return Err(AnthelionError::invalid("Installer URLs must not be empty"));
    }

    // `Url` also serves the CLI and treats a literal pipe as its architecture delimiter.
    // Architecture is a separate API field here, so preserve literal pipes as URL data.
    let escaped = url.replace('|', "%7C");
    escaped
        .parse()
        .map_err(|error| AnthelionError::invalid(format!("Invalid installer URL {url:?}: {error}")))
}

pub async fn analyze_sources(
    downloader: Arc<Downloader>,
    concurrency: NonZeroUsize,
    sources: Vec<InstallerSource>,
) -> AnthelionResult<Vec<ArtifactAnalysis>> {
    if sources.is_empty() {
        return Err(AnthelionError::invalid(
            "At least one installer is required",
        ));
    }

    let parsed_sources = sources
        .into_iter()
        .map(|source| {
            Ok((
                parse_installer_url(&source.url)?,
                source
                    .architecture
                    .map(|architecture| parse_architecture(&architecture))
                    .transpose()?,
                source.nested_installer_matches.unwrap_or_default(),
            ))
        })
        .collect::<AnthelionResult<Vec<_>>>()?;
    let unique_urls = parsed_sources
        .iter()
        .map(|(url, _, matches)| {
            (
                AnalysisKey {
                    url: url.original_url().to_string(),
                    nested_installer_matches: matches.clone(),
                },
                url.clone(),
            )
        })
        .collect::<IndexMap<_, _>>();

    // Keep the original URL beside each future: downloads may resolve GitHub `latest` links or
    // fall back from decoded URLs, either of which changes the URL stored in the result.
    let analyzed_by_url = stream::iter(unique_urls)
        .map(|(source_key, url)| {
            let downloader = Arc::clone(&downloader);
            async move {
                let mut files = downloader.download([url]).await.map_err(|error| {
                    AnthelionError::failure(
                        ErrorCode::AnalysisFailed,
                        error.wrap_err(format!("Failed to download installer {}", source_key.url)),
                    )
                })?;
                let file = files.pop().ok_or_else(|| {
                    AnthelionError::failure(
                        ErrorCode::AnalysisFailed,
                        eyre!("Downloader returned no file for {}", source_key.url),
                    )
                })?;
                let nested_installer_matches = source_key.nested_installer_matches.clone();
                let analysis = tokio::task::spawn_blocking(move || {
                    analyze_download(file, &nested_installer_matches)
                })
                .await
                .map_err(|error| {
                    AnthelionError::failure(
                        ErrorCode::AnalysisFailed,
                        Report::from(error).wrap_err("Installer analysis task failed"),
                    )
                })??;
                Ok::<_, AnthelionError>((source_key, analysis))
            }
        })
        .buffer_unordered(concurrency.get())
        .try_collect::<std::collections::HashMap<_, _>>()
        .await?;

    parsed_sources
        .into_iter()
        .map(|(source, architecture, nested_installer_matches)| {
            let source_key = AnalysisKey {
                url: source.original_url().to_string(),
                nested_installer_matches,
            };
            let mut analysis = analyzed_by_url.get(&source_key).cloned().ok_or_else(|| {
                AnthelionError::failure(
                    ErrorCode::AnalysisFailed,
                    eyre!("No analysis was returned for {source}"),
                )
            })?;
            if let Some(architecture) = architecture {
                for installer in &mut analysis.installers {
                    installer.architecture = architecture;
                }
            }
            Ok(analysis)
        })
        .collect()
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AnalysisKey {
    url: String,
    nested_installer_matches: Vec<String>,
}

fn parse_architecture(input: &str) -> AnthelionResult<winget_types::installer::Architecture> {
    use winget_types::installer::Architecture;

    match input {
        "x86" => Ok(Architecture::X86),
        "x64" => Ok(Architecture::X64),
        "arm" => Ok(Architecture::Arm),
        "arm64" => Ok(Architecture::Arm64),
        "neutral" => Ok(Architecture::Neutral),
        _ => Err(AnthelionError::invalid(format!(
            "Invalid installer architecture {input:?}"
        ))),
    }
}

fn analyze_download(
    mut file: DownloadedFile,
    nested_installer_matches: &[String],
) -> AnthelionResult<ArtifactAnalysis> {
    let mut analyzer = Analyzer::new(&mut file.file, &file.file_name).map_err(|error| {
        AnthelionError::failure(
            ErrorCode::AnalysisFailed,
            error.wrap_err(format!("Failed to analyze {}", file.file_name)),
        )
    })?;

    if let Some(zip) = &mut analyzer.zip
        && !nested_installer_matches.is_empty()
    {
        let matched = zip
            .analyze_matches_with_metadata(nested_installer_matches)
            .map_err(|error| {
                AnthelionError::failure(
                    ErrorCode::AnalysisFailed,
                    error.wrap_err(format!(
                        "Failed to analyze matching installers in {}",
                        file.file_name
                    )),
                )
            })?;

        analyzer.file_version = first_non_empty(
            matched
                .iter()
                .filter_map(|analysis| analysis.file_version.as_deref()),
        )
        .or(analyzer.file_version);
        analyzer.product_version = first_non_empty(
            matched
                .iter()
                .filter_map(|analysis| analysis.product_version.as_deref()),
        )
        .or(analyzer.product_version);
        analyzer.installers = matched
            .into_iter()
            .map(|analysis| analysis.installer)
            .collect();
    }

    let architecture = file
        .url
        .override_architecture()
        .or_else(|| winget_types::installer::Architecture::from_url(file.url.as_str()));
    for installer in &mut analyzer.installers {
        if let Some(architecture) = architecture {
            installer.architecture = architecture;
        }
        installer.url = file.url.inner().clone();
        installer.sha_256 = file.sha_256.clone();
        installer.release_date = file.last_modified;
    }

    let possible_installer_files = analyzer
        .zip
        .as_ref()
        .map(|zip| zip.possible_installer_files.clone())
        .unwrap_or_default();

    Ok(ArtifactAnalysis {
        url: file.url.into_inner(),
        sha256: file.sha_256,
        release_date: file.last_modified,
        file_version: analyzer.file_version,
        product_version: analyzer.product_version,
        installers: analyzer.installers,
        possible_installer_files,
    })
}

fn first_non_empty<'a>(values: impl Iterator<Item = &'a str>) -> Option<String> {
    values
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_owned)
}

impl From<ArtifactAnalysis> for AnalyzedArtifact {
    fn from(analysis: ArtifactAnalysis) -> Self {
        Self {
            url: analysis.url.to_string(),
            sha256: analysis.sha256.to_string(),
            release_date: analysis.release_date.map(|date| date.to_string()),
            versions: DetectedVersions {
                file: analysis.file_version,
                product: analysis.product_version,
            },
            installers: analysis
                .installers
                .into_iter()
                .map(AnalyzedInstaller::from)
                .collect(),
        }
    }
}

impl From<Installer> for AnalyzedInstaller {
    fn from(installer: Installer) -> Self {
        Self {
            locale: installer.locale.map(|locale| locale.to_string()),
            architecture: installer.architecture.to_string(),
            installer_type: installer
                .r#type
                .map(|installer_type| installer_type.to_string()),
            nested_installer_type: installer
                .nested_installer_type
                .map(|installer_type| installer_type.to_string()),
            nested_installer_files: installer
                .nested_installer_files
                .into_iter()
                .map(|file| file.relative_file_path.to_string())
                .collect(),
            apps_and_features_entries: installer
                .apps_and_features_entries
                .into_iter()
                .map(|entry| AppsAndFeaturesEntry {
                    display_name: entry.display_name().map(str::to_owned),
                    publisher: entry.publisher().map(str::to_owned),
                    display_version: entry.display_version().map(ToString::to_string),
                    product_code: entry.product_code().map(str::to_owned),
                    upgrade_code: entry.upgrade_code().map(str::to_owned),
                    installer_type: entry
                        .installer_type()
                        .map(|installer_type| installer_type.to_string()),
                })
                .collect(),
            scope: installer.scope.map(|scope| scope.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AnalysisKey, parse_installer_url};

    #[test]
    fn keeps_architecture_out_of_the_url() {
        let url = parse_installer_url("https://example.com/app.exe").unwrap();

        assert_eq!(url.as_str(), "https://example.com/app.exe");
        assert_eq!(url.override_architecture(), None);
    }

    #[test]
    fn preserves_literal_url_pipes() {
        let url = parse_installer_url("https://example.com/download|stable/app.exe").unwrap();

        assert_eq!(url.as_str(), "https://example.com/download|stable/app.exe");
        assert_eq!(
            url.original_url().as_str(),
            "https://example.com/download%7Cstable/app.exe"
        );
    }

    #[test]
    fn nested_match_rules_are_part_of_the_analysis_cache_key() {
        let url = "https://example.com/archive.zip".to_owned();
        let first = AnalysisKey {
            url: url.clone(),
            nested_installer_matches: vec!["first.exe".to_owned()],
        };
        let second = AnalysisKey {
            url,
            nested_installer_matches: vec!["second.exe".to_owned()],
        };

        assert_ne!(first, second);
    }
}
