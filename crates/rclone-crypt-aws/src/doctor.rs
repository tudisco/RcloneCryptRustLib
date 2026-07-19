//! Conservative cleanup of abandoned S3 multipart uploads.

use std::{
    collections::HashSet,
    time::{Duration, SystemTime},
};

use aws_sdk_s3::Client;
use rclone_crypt::{Error, Result};

const MINIMUM_GRACE_PERIOD: Duration = Duration::from_secs(60 * 60);
const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// Safety controls for a multipart-upload cleanup scan.
#[derive(Clone, Debug)]
pub struct DoctorOptions {
    /// Only uploads whose keys begin with this non-empty prefix are inspected.
    pub prefix: String,
    /// An upload must be at least this old before it can be aborted.
    pub stale_after: Duration,
    /// Perform aborts. `false` is a side-effect-free dry run.
    pub apply: bool,
    /// Upload IDs known to belong to currently running application instances.
    pub active_upload_ids: HashSet<String>,
    /// Maximum abort actions in one run.
    pub max_actions: usize,
    /// Abort/verification attempts, covering parts that finish concurrently.
    pub max_abort_attempts: u8,
}

impl DoctorOptions {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<()> {
        if self.prefix.is_empty() {
            return Err(Error::Source(
                "store doctor requires a non-empty prefix".into(),
            ));
        }
        if self.stale_after < MINIMUM_GRACE_PERIOD {
            return Err(Error::Source(
                "store doctor grace period must be at least one hour".into(),
            ));
        }
        if self.max_actions == 0 {
            return Err(Error::Source(
                "store doctor max_actions must be non-zero".into(),
            ));
        }
        if self.max_abort_attempts == 0 {
            return Err(Error::Source(
                "store doctor max_abort_attempts must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

impl Default for DoctorOptions {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            stale_after: DEFAULT_GRACE_PERIOD,
            apply: false,
            active_upload_ids: HashSet::new(),
            max_actions: 100,
            max_abort_attempts: 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingDisposition {
    Active,
    Recent,
    MissingMetadata,
    WouldAbort,
    AbortedAndVerified,
    ActionLimitReached,
    Failed,
}

#[derive(Clone, Debug)]
pub struct DoctorFinding {
    pub key: String,
    pub upload_id: String,
    pub initiated: Option<SystemTime>,
    pub age: Option<Duration>,
    pub uploaded_part_bytes: Option<u64>,
    pub disposition: FindingDisposition,
}

#[derive(Clone, Debug)]
pub struct DoctorFailure {
    pub key: String,
    pub upload_id: String,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct DoctorReport {
    pub scanned: usize,
    pub stale: usize,
    pub active: usize,
    pub recent: usize,
    pub proposed: usize,
    pub aborted: usize,
    pub verified_reclaimed_bytes: u64,
    pub action_limit_reached: bool,
    pub findings: Vec<DoctorFinding>,
    pub failures: Vec<DoctorFailure>,
}

/// Scans and optionally aborts abandoned multipart uploads in one bucket.
#[derive(Clone, Debug)]
pub struct StoreDoctor {
    client: Client,
    bucket: String,
}

impl StoreDoctor {
    pub fn new(client: Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }

    pub async fn run(&self, options: &DoctorOptions) -> Result<DoctorReport> {
        self.run_at(options, SystemTime::now()).await
    }

    async fn run_at(&self, options: &DoctorOptions, now: SystemTime) -> Result<DoctorReport> {
        options.validate()?;
        let mut report = DoctorReport::default();
        let mut key_marker: Option<String> = None;
        let mut upload_marker: Option<String> = None;
        let mut actions = 0_usize;

        loop {
            let mut request = self
                .client
                .list_multipart_uploads()
                .bucket(&self.bucket)
                .prefix(&options.prefix);
            if let Some(marker) = &key_marker {
                request = request.key_marker(marker);
            }
            if let Some(marker) = &upload_marker {
                request = request.upload_id_marker(marker);
            }
            let page = request.send().await.map_err(|error| {
                Error::Source(format!("S3 ListMultipartUploads failed: {error}"))
            })?;

            // Own the page data so repair requests do not retain the response.
            let uploads: Vec<_> = page
                .uploads()
                .iter()
                .map(|upload| {
                    let initiated = upload
                        .initiated()
                        .and_then(|value| SystemTime::try_from(*value).ok());
                    (
                        upload.key().map(ToOwned::to_owned),
                        upload.upload_id().map(ToOwned::to_owned),
                        initiated,
                    )
                })
                .collect();
            let truncated = page.is_truncated().unwrap_or(false);
            let next_key = page.next_key_marker().map(ToOwned::to_owned);
            let next_upload = page.next_upload_id_marker().map(ToOwned::to_owned);

            for (key, upload_id, initiated) in uploads {
                report.scanned += 1;
                if key.is_none() || upload_id.is_none() || initiated.is_none() {
                    report.findings.push(DoctorFinding {
                        key: key.unwrap_or_default(),
                        upload_id: upload_id.unwrap_or_default(),
                        initiated,
                        age: None,
                        uploaded_part_bytes: None,
                        disposition: FindingDisposition::MissingMetadata,
                    });
                    continue;
                }
                let key = key.expect("checked above");
                let upload_id = upload_id.expect("checked above");
                let initiated = initiated.expect("checked above");
                let age = now.duration_since(initiated).ok();
                if options.active_upload_ids.contains(&upload_id) {
                    report.active += 1;
                    report.findings.push(finding(
                        key,
                        upload_id,
                        initiated,
                        age,
                        None,
                        FindingDisposition::Active,
                    ));
                    continue;
                }
                if age.is_none_or(|age| age < options.stale_after) {
                    report.recent += 1;
                    report.findings.push(finding(
                        key,
                        upload_id,
                        initiated,
                        age,
                        None,
                        FindingDisposition::Recent,
                    ));
                    continue;
                }
                report.stale += 1;
                report.proposed += 1;
                let part_bytes = match self.uploaded_part_bytes(&key, &upload_id).await {
                    Ok(bytes) => Some(bytes),
                    Err(message) => {
                        report.failures.push(DoctorFailure {
                            key: key.clone(),
                            upload_id: upload_id.clone(),
                            message,
                        });
                        None
                    }
                };
                if !options.apply {
                    report.findings.push(finding(
                        key,
                        upload_id,
                        initiated,
                        age,
                        part_bytes,
                        FindingDisposition::WouldAbort,
                    ));
                    continue;
                }
                if actions >= options.max_actions {
                    report.action_limit_reached = true;
                    report.findings.push(finding(
                        key,
                        upload_id,
                        initiated,
                        age,
                        part_bytes,
                        FindingDisposition::ActionLimitReached,
                    ));
                    continue;
                }
                actions += 1;
                match self
                    .abort_and_verify(&key, &upload_id, options.max_abort_attempts)
                    .await
                {
                    Ok(()) => {
                        report.aborted += 1;
                        report.verified_reclaimed_bytes = report
                            .verified_reclaimed_bytes
                            .checked_add(part_bytes.unwrap_or(0))
                            .ok_or(Error::RangeOverflow)?;
                        report.findings.push(finding(
                            key,
                            upload_id,
                            initiated,
                            age,
                            part_bytes,
                            FindingDisposition::AbortedAndVerified,
                        ));
                    }
                    Err(message) => {
                        report.failures.push(DoctorFailure {
                            key: key.clone(),
                            upload_id: upload_id.clone(),
                            message,
                        });
                        report.findings.push(finding(
                            key,
                            upload_id,
                            initiated,
                            age,
                            part_bytes,
                            FindingDisposition::Failed,
                        ));
                    }
                }
            }

            if !truncated {
                break;
            }
            if next_key.is_none() {
                return Err(Error::Source(
                    "S3 returned a truncated multipart listing without a continuation marker"
                        .into(),
                ));
            }
            key_marker = next_key;
            upload_marker = next_upload;
        }
        Ok(report)
    }

    async fn uploaded_part_bytes(
        &self,
        key: &str,
        upload_id: &str,
    ) -> std::result::Result<u64, String> {
        let mut marker: Option<String> = None;
        let mut total = 0_u64;
        loop {
            let mut request = self
                .client
                .list_parts()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(upload_id);
            if let Some(marker) = &marker {
                request = request.part_number_marker(marker);
            }
            let page = request
                .send()
                .await
                .map_err(|error| format!("S3 ListParts failed: {error}"))?;
            for part in page.parts() {
                let size = part.size().unwrap_or(0);
                let size = u64::try_from(size)
                    .map_err(|_| "S3 returned a negative multipart part size".to_owned())?;
                total = total
                    .checked_add(size)
                    .ok_or_else(|| "multipart part byte count overflowed".to_owned())?;
            }
            if !page.is_truncated().unwrap_or(false) {
                break;
            }
            marker = page.next_part_number_marker().map(ToOwned::to_owned);
            if marker.is_none() {
                return Err("S3 returned truncated parts without a continuation marker".into());
            }
        }
        Ok(total)
    }

    async fn abort_and_verify(
        &self,
        key: &str,
        upload_id: &str,
        attempts: u8,
    ) -> std::result::Result<(), String> {
        crate::abort_multipart_verified(
            &self.client,
            &self.bucket,
            key,
            upload_id,
            attempts,
            Duration::from_millis(200),
        )
        .await
    }
}

fn finding(
    key: String,
    upload_id: String,
    initiated: SystemTime,
    age: Option<Duration>,
    uploaded_part_bytes: Option<u64>,
    disposition: FindingDisposition,
) -> DoctorFinding {
    DoctorFinding {
        key,
        upload_id,
        initiated: Some(initiated),
        age,
        uploaded_part_bytes,
        disposition,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_dry_run_and_bounded() {
        let options = DoctorOptions::new("test-prefix/");
        assert!(!options.apply);
        assert_eq!(options.stale_after, Duration::from_secs(86_400));
        assert_eq!(options.max_actions, 100);
        options.validate().unwrap();
    }

    #[test]
    fn rejects_dangerous_scope_and_grace_period() {
        assert!(DoctorOptions::default().validate().is_err());
        let mut options = DoctorOptions::new("safe/");
        options.stale_after = Duration::from_secs(3599);
        assert!(options.validate().is_err());
    }

    /// Creates a real abandoned upload with one part, proves dry-run does not
    /// mutate it, then applies and verifies cleanup. Run explicitly with the
    /// same B2_* environment variables used by the other live tests.
    #[tokio::test]
    #[ignore = "requires temporary Backblaze B2 credentials"]
    async fn live_b2_abandoned_upload_cleanup() {
        use aws_sdk_s3::{
            config::{BehaviorVersion, Credentials, Region},
            primitives::ByteStream,
        };
        use bytes::Bytes;

        let required =
            |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"));
        let bucket = required("B2_BUCKET");
        let prefix = format!(
            "{}/doctor-live-{}",
            required("B2_PREFIX"),
            std::process::id()
        );
        let credentials = Credentials::new(
            required("B2_KEY_ID"),
            required("B2_APPLICATION_KEY"),
            None,
            None,
            "doctor-live-test",
        );
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(credentials)
            .region(Region::new(required("B2_REGION")))
            .endpoint_url(required("B2_ENDPOINT"))
            .force_path_style(true)
            .build();
        let client = Client::from_conf(config);
        let key = format!("{prefix}/abandoned.bin");
        let created = client
            .create_multipart_upload()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .unwrap();
        let upload_id = created.upload_id().unwrap().to_owned();
        let mut guard = crate::MultipartAbortGuard::new(
            client.clone(),
            bucket.clone(),
            key.clone(),
            upload_id.clone(),
        );
        client
            .upload_part()
            .bucket(&bucket)
            .key(&key)
            .upload_id(&upload_id)
            .part_number(1)
            .body(ByteStream::from(Bytes::from(vec![0_u8; 5 * 1024 * 1024])))
            .send()
            .await
            .unwrap();

        let doctor = StoreDoctor::new(client, bucket);
        let mut options = DoctorOptions::new(prefix);
        options.stale_after = MINIMUM_GRACE_PERIOD;
        let future = SystemTime::now() + Duration::from_secs(2 * 60 * 60);
        let dry_run = doctor.run_at(&options, future).await.unwrap();
        assert_eq!(dry_run.proposed, 1);
        assert_eq!(dry_run.aborted, 0);
        assert_eq!(
            dry_run.findings[0].uploaded_part_bytes,
            Some(5 * 1024 * 1024)
        );

        options.apply = true;
        let applied = doctor.run_at(&options, future).await.unwrap();
        assert_eq!(applied.aborted, 1);
        assert_eq!(applied.verified_reclaimed_bytes, 5 * 1024 * 1024);
        guard.disarm();

        let repeated = doctor.run_at(&options, future).await.unwrap();
        assert_eq!(repeated.scanned, 0);
        assert_eq!(repeated.aborted, 0);
    }
}
