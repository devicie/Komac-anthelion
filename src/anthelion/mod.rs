mod analyze_installer;
mod client;
mod error;
mod release_notes;
mod types;
mod update_helpers;
mod update_version;

pub use analyze_installer::analyze_installer;
pub use get_existing_pull_request::get_existing_pull_request;
pub use release_notes::{
    get_formatted_github_release_notes, html_to_plain_text, markdown_to_plain_text,
};
pub use types::{
    AnalyzeInstallerResult, AppsAndFeaturesEntryAnalysis, ExistingPullRequestResult,
    GetExistingPullRequestOptions, InstallerAnalysis, ManifestChange, NestedInstallerFileAnalysis,
    UpdateVersionOptions, UpdateVersionResult,
};
pub use update_version::update_version;
pub use client::Komac;
pub use release_notes::release_notes_to_plain_text;
pub use types::*;
pub use yaml::parse_yaml;
