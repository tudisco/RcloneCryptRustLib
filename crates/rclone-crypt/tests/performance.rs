use std::{sync::Arc, time::Instant};

use rclone_crypt::{Credential, Keys, MemorySource, RcloneCryptObject};

#[tokio::test]
#[ignore = "run explicitly with RCLONE_CIPHERTEXT_FILE"]
async fn sequential_decryption_throughput() {
    let path = std::env::var("RCLONE_CIPHERTEXT_FILE").unwrap();
    let password = std::env::var("RCLONE_BENCH_PASSWORD").unwrap();
    let salt = std::env::var("RCLONE_BENCH_SALT").unwrap();
    let encrypted = tokio::fs::read(path).await.unwrap();
    let keys = Keys::derive(&Credential::Clear(password), Some(&Credential::Clear(salt))).unwrap();
    let object = Arc::new(
        RcloneCryptObject::open(Arc::new(MemorySource::new(encrypted)), keys)
            .await
            .unwrap(),
    );
    let mut reader = object.reader();
    let mut sink = tokio::io::sink();
    let started = Instant::now();
    let bytes = tokio::io::copy(&mut reader, &mut sink).await.unwrap();
    let elapsed = started.elapsed();
    let mib_per_second = bytes as f64 / 1_048_576.0 / elapsed.as_secs_f64();
    eprintln!(
        "decrypted {bytes} bytes in {:.3}s: {:.1} MiB/s",
        elapsed.as_secs_f64(),
        mib_per_second
    );
}
