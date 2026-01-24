use anyhow::Result;
#[cfg(target_os = "linux")]
use log::{info, warn};
#[cfg(target_os = "linux")]
use self_update::cargo_crate_version;

#[cfg(target_os = "linux")]
const REPO_OWNER: &str = "hapara-fail";
#[cfg(target_os = "linux")]
const REPO_NAME: &str = "nx53";
const BIN_NAME: &str = "nx53";
#[cfg(target_os = "linux")]
const UPDATE_TARGET: &str = "linux-x86_64";

#[cfg(target_os = "linux")]
pub fn update() -> Result<()> {
    let status = self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .target(UPDATE_TARGET)
        .current_version(cargo_crate_version!())
        .show_download_progress(true)
        .build()?
        .update()?;

    println!("Update status: `{}`!", status.version());
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn check_for_updates() -> Result<()> {
    // Skip update check in debug builds unless explicitly enabled to avoid API rate limits.
    if cfg!(debug_assertions) && std::env::var("NX53_CHECK_UPDATES").is_err() {
        info!("Skipping update check in debug build; set NX53_CHECK_UPDATES=1 to enable.");
        return Ok(());
    }

    let releases = self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .target(UPDATE_TARGET)
        .current_version(cargo_crate_version!())
        .build()?
        .get_latest_release()?;

    let current = cargo_crate_version!();
    if self_update::version::bump_is_greater(current, &releases.version)? {
        warn!(
            "Update available! v{} -> v{} (Run '{} update' to upgrade)",
            current, releases.version, BIN_NAME
        );
    } else {
        info!("{} is up to date (v{})", BIN_NAME, current);
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn update() -> Result<()> {
    println!("Auto-update for {} is only supported on Linux.", BIN_NAME);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn check_for_updates() -> Result<()> {
    println!(
        "Update checks for {} are only supported on Linux.",
        BIN_NAME
    );
    Ok(())
}

pub fn print_version() {
    println!("{} v{}", BIN_NAME, env!("CARGO_PKG_VERSION"));
}
