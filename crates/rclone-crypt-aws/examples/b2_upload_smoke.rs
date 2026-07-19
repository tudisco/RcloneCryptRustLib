use std::path::PathBuf;

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
};
use rclone_crypt::{Credential, Keys, NameCipher};
use rclone_crypt_aws::{S3Uploader, UploadOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_id = required("B2_KEY_ID")?;
    let application_key = required("B2_APPLICATION_KEY")?;
    let endpoint = required("B2_ENDPOINT")?;
    let region = required("B2_REGION")?;
    let bucket = required("B2_BUCKET")?;
    let prefix = required("B2_PREFIX")?;
    let plaintext_name = required("PLAINTEXT_NAME")?;
    let plaintext_path = PathBuf::from(required("PLAINTEXT_PATH")?);
    let password = required("RCLONE_PASSWORD")?;
    let salt = required("RCLONE_SALT")?;

    let credentials = Credentials::new(key_id, application_key, None, None, "b2-upload-test");
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .credentials_provider(credentials)
        .region(Region::new(region))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .build();
    let keys = Keys::derive(&Credential::Clear(password), Some(&Credential::Clear(salt)))?;
    let encrypted_name = NameCipher::new(&keys).encrypt_path(&plaintext_name)?;
    let encrypted_key = format!("{prefix}/{encrypted_name}");
    let mut plaintext = tokio::fs::File::open(plaintext_path).await?;
    let result = S3Uploader::new(Client::from_conf(config), bucket)
        .upload_reader(
            &mut plaintext,
            encrypted_key,
            &keys,
            UploadOptions::default(),
        )
        .await?;
    println!(
        "uploaded {} plaintext bytes as {} encrypted bytes to {}",
        result.stats.plaintext_bytes, result.stats.encrypted_bytes, result.encrypted_key
    );
    Ok(())
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("missing {name}").into())
}
