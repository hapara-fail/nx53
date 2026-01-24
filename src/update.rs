use anyhow::Result;
#[cfg(target_os = "linux")]
use log::{info, warn};
#[cfg(target_os = "linux")]
use self_update::cargo_crate_version;

#[cfg(target_os = "linux")]
pub fn update() -> Result<()> {
    let status = self_update::backends::github::Update::configure()
        .repo_owner("hapara-fail")
        .repo_name("nx53")
        .bin_name("nx53")
        .target("linux-x86_64")
        .show_download_progress(true)
        .current_version(cargo_crate_version!())
        .build()?
        .update()?;

    println!("Update status: `{}`!", status.version());
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn check_for_updates() -> Result<()> {
    // Only check in release mode or if explicitly requested to avoid api rate limits during dev?
    // For now just check.
    let releases = self_update::backends::github::Update::configure()
        .repo_owner("hapara-fail")
        .repo_name("nx53")
        .bin_name("nx53")
        .target("linux-x86_64")
        .current_version(cargo_crate_version!())
        .build()?
        .get_latest_release()?;

    let current = cargo_crate_version!();
    if self_update::version::bump_is_greater(current, &releases.version)? {
        warn!(
            "Update available! v{} -> v{} (Run 'nx53 update' to upgrade)",
            current, releases.version
        );
    } else {
        info!("nx53 is up to date (v{})", current);
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn update() -> Result<()> {
    println!("Auto-update is only supported on Linux.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn check_for_updates() -> Result<()> {
    println!("Update checks are only supported on Linux.");
    Ok(())
}

pub fn print_version() {
    println!("nx53 v{}", env!("CARGO_PKG_VERSION"));
}
