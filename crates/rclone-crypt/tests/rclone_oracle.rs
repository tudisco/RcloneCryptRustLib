use std::{fs, path::Path, process::Command, sync::Arc};

use rclone_crypt::{Credential, Keys, MemorySource, NameCipher, RcloneCryptObject, encrypt_to};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const PASSWORD: &str = "correct horse battery staple";
const SALT: &str = "salty ünicode";

fn rclone() -> Option<String> {
    std::env::var("RCLONE_TEST_BINARY").ok()
}

fn output(binary: &str, args: &[&str]) -> String {
    let result = Command::new(binary).args(args).output().unwrap();
    assert!(
        result.status.success(),
        "rclone failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

fn write_config(binary: &str, root: &Path, config: &Path) {
    let password = output(binary, &["obscure", PASSWORD]);
    let salt = output(binary, &["obscure", SALT]);
    fs::write(
        config,
        format!(
            "[crypt]\ntype = crypt\nremote = {}\npassword = {password}\npassword2 = {salt}\nfilename_encryption = standard\ndirectory_name_encryption = true\nfilename_encoding = base32\n",
            root.display()
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn decrypts_files_created_by_pinned_rclone() {
    let Some(binary) = rclone() else {
        eprintln!("skipped: set RCLONE_TEST_BINARY to the pinned v1.74.2 executable");
        return;
    };
    let version = output(&binary, &["version"]);
    assert!(version.starts_with("rclone v1.74.2\n"), "{version}");

    let temp = tempfile::tempdir().unwrap();
    let encrypted = temp.path().join("encrypted");
    let plaintext = temp.path().join("plaintext");
    let config = temp.path().join("rclone.conf");
    fs::create_dir_all(&encrypted).unwrap();
    fs::create_dir_all(&plaintext).unwrap();
    write_config(&binary, &encrypted, &config);

    let cases = [
        ("empty", Vec::new()),
        ("one.bin", vec![0x5a]),
        ("exact.bin", pattern(65_536)),
        ("mañana 東京.mp4", pattern(65_537)),
        ("multi.bin", pattern(65_536 * 3 + 123)),
    ];

    let keys = Keys::derive(
        &Credential::Clear(PASSWORD.into()),
        Some(&Credential::Clear(SALT.into())),
    )
    .unwrap();

    for (name, expected) in cases {
        let source_path = plaintext.join(name);
        fs::write(&source_path, &expected).unwrap();
        let status = Command::new(&binary)
            .args(["--config", config.to_str().unwrap(), "copyto"])
            .arg(&source_path)
            .arg(format!("crypt:{name}"))
            .status()
            .unwrap();
        assert!(status.success());

        let encoded = output(
            &binary,
            &[
                "--config",
                config.to_str().unwrap(),
                "backend",
                "encode",
                "crypt:",
                name,
            ],
        );
        let name_cipher = NameCipher::new(&keys);
        assert_eq!(name_cipher.decrypt_path(&encoded).unwrap(), name);
        assert_eq!(name_cipher.encrypt_path(name).unwrap(), encoded);
        let encrypted_path = encrypted.join(&encoded);
        let ciphertext = fs::read(&encrypted_path).unwrap();
        let object = Arc::new(
            RcloneCryptObject::open(Arc::new(MemorySource::new(ciphertext)), keys.clone())
                .await
                .unwrap(),
        );
        assert_eq!(object.plaintext_len(), expected.len() as u64);
        assert_eq!(
            object.read_range(0..expected.len() as u64).await.unwrap(),
            expected
        );

        if expected.len() > 65_536 {
            let start = 65_530_u64;
            let end = (65_536 + 20).min(expected.len()) as u64;
            assert_eq!(
                object.read_range(start..end).await.unwrap(),
                expected[start as usize..end as usize]
            );

            let mut reader = object.reader().with_fetch_size(70_000);
            reader.seek(std::io::SeekFrom::Start(start)).await.unwrap();
            let mut probe = vec![0_u8; (end - start) as usize];
            reader.read_exact(&mut probe).await.unwrap();
            assert_eq!(probe, expected[start as usize..end as usize]);

            reader.seek(std::io::SeekFrom::End(-32)).await.unwrap();
            let mut tail = Vec::new();
            reader.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, expected[expected.len() - 32..]);

            reader.seek(std::io::SeekFrom::Start(0)).await.unwrap();
            let mut complete = Vec::new();
            reader.read_to_end(&mut complete).await.unwrap();
            assert_eq!(complete, expected);
        }

        // Reverse direction: Rust encrypts and pinned rclone must authenticate/decrypt it.
        let mut plaintext_reader = std::io::Cursor::new(expected.clone());
        let mut rust_ciphertext = Vec::new();
        encrypt_to(&mut plaintext_reader, &mut rust_ciphertext, &keys)
            .await
            .unwrap();
        fs::write(&encrypted_path, rust_ciphertext).unwrap();
        let result = Command::new(&binary)
            .args(["--config", config.to_str().unwrap(), "cat"])
            .arg(format!("crypt:{name}"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "rclone rejected Rust upload: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, expected);
    }
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index.wrapping_mul(31).wrapping_add(17) % 251) as u8)
        .collect()
}
