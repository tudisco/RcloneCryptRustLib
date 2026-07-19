use std::{path::PathBuf, sync::Arc};

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
};
use rclone_crypt::{Credential, DownloadOptions, Keys, RcloneCryptObject};
use rclone_crypt_aws::S3RangeSource;
use sha2::{Digest, Sha256};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_id = required("B2_KEY_ID")?;
    let application_key = required("B2_APPLICATION_KEY")?;
    let endpoint = required("B2_ENDPOINT")?;
    let region = required("B2_REGION")?;
    let bucket = required("B2_BUCKET")?;
    let object_key = required("B2_OBJECT_KEY")?;
    let password = required("RCLONE_PASSWORD")?;
    let salt = required("RCLONE_SALT")?;
    let expected_path = PathBuf::from(required("EXPECTED_PLAINTEXT")?);
    let output_path = PathBuf::from(required("OUTPUT_PATH")?);

    let credentials = Credentials::new(key_id, application_key, None, None, "b2-live-test");
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .credentials_provider(credentials)
        .region(Region::new(region))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .build();
    let client = Client::from_conf(config);
    let source = Arc::new(S3RangeSource::new(client, bucket, object_key));
    let keys = Keys::derive(&Credential::Clear(password), Some(&Credential::Clear(salt)))?;
    let object = Arc::new(RcloneCryptObject::open(source, keys).await?);
    let expected = tokio::fs::read(&expected_path).await?;
    if object.plaintext_len() != expected.len() as u64 {
        return Err("plaintext size mismatch".into());
    }

    let ranges = range_matrix(expected.len() as u64);
    for range in ranges {
        let actual = object.read_range(range.clone()).await?;
        if actual.as_ref() != &expected[range.start as usize..range.end as usize] {
            return Err(format!("range mismatch for {range:?}").into());
        }
    }

    object
        .download_to(
            &output_path,
            DownloadOptions {
                overwrite: true,
                create_parent: true,
                sync_data: false,
            },
        )
        .await?;
    let downloaded = tokio::fs::read(&output_path).await?;
    if Sha256::digest(&downloaded) != Sha256::digest(&expected) {
        return Err("downloaded SHA-256 mismatch".into());
    }
    println!(
        "verified {} plaintext bytes across {} ranges and atomic download",
        expected.len(),
        range_matrix(expected.len() as u64).len()
    );
    Ok(())
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("missing {name}").into())
}

fn range_matrix(size: u64) -> Vec<std::ops::Range<u64>> {
    let mut ranges = Vec::new();
    ranges.push(0..size.min(1024));
    if size > 1 {
        ranges.push(size - 1..size);
        ranges.push(size.saturating_sub(4096)..size);
    }
    for boundary in [65_536_u64, 131_072, 1_048_576, size / 2] {
        if boundary > 8 && boundary + 8 < size {
            ranges.push(boundary - 8..boundary + 8);
        }
    }
    ranges
}
