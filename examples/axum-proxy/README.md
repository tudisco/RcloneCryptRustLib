# Axum image/video proxy

The proxy maps plaintext URL paths to rclone standard-encrypted S3 keys and
serves authenticated plaintext with `GET`, `HEAD`, and single HTTP byte ranges.

Required environment variables:

- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`
- `RCLONE_CRYPT_PASSWORD`

Optional: `RCLONE_CRYPT_SALT`, `S3_PREFIX`, `LISTEN_ADDR`, and
`PROXY_BEARER_TOKEN`. Bind to localhost or set a bearer token; production
deployments should place TLS and authorization at a trusted ingress.

Run with `cargo run -p rclone-crypt-axum-proxy`.
