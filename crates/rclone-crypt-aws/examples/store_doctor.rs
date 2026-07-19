use std::{collections::HashSet, time::Duration};

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
};
use rclone_crypt_aws::{DoctorOptions, StoreDoctor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let apply = std::env::args().any(|argument| argument == "--apply");
    let key_id = required("B2_KEY_ID")?;
    let application_key = required("B2_APPLICATION_KEY")?;
    let endpoint = required("B2_ENDPOINT")?;
    let region = required("B2_REGION")?;
    let bucket = required("B2_BUCKET")?;
    let prefix = required("B2_PREFIX")?;
    let stale_hours = std::env::var("DOCTOR_STALE_HOURS")
        .unwrap_or_else(|_| "24".into())
        .parse::<u64>()?;
    let active_upload_ids = std::env::var("DOCTOR_ACTIVE_UPLOAD_IDS")
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<HashSet<_>>();

    let credentials = Credentials::new(key_id, application_key, None, None, "store-doctor");
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .credentials_provider(credentials)
        .region(Region::new(region))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .build();
    let mut options = DoctorOptions::new(prefix);
    options.stale_after = Duration::from_secs(
        stale_hours
            .checked_mul(60 * 60)
            .ok_or("DOCTOR_STALE_HOURS is too large")?,
    );
    options.apply = apply;
    options.active_upload_ids = active_upload_ids;

    let report = StoreDoctor::new(Client::from_conf(config), bucket)
        .run(&options)
        .await?;
    println!(
        "mode={} scanned={} stale={} active={} recent={} proposed={} aborted={} reclaimed_part_bytes={} failures={} action_limit_reached={}",
        if apply { "APPLY" } else { "DRY-RUN" },
        report.scanned,
        report.stale,
        report.active,
        report.recent,
        report.proposed,
        report.aborted,
        report.verified_reclaimed_bytes,
        report.failures.len(),
        report.action_limit_reached,
    );
    for finding in &report.findings {
        println!(
            "{:?} key={:?} upload_id={:?} age_seconds={:?} uploaded_part_bytes={:?}",
            finding.disposition,
            finding.key,
            finding.upload_id,
            finding.age.map(|age| age.as_secs()),
            finding.uploaded_part_bytes,
        );
    }
    for failure in &report.failures {
        eprintln!(
            "FAILED key={:?} upload_id={:?}: {}",
            failure.key, failure.upload_id, failure.message
        );
    }
    if !report.failures.is_empty() {
        return Err("one or more cleanup operations failed".into());
    }
    Ok(())
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("missing {name}").into())
}
