use std::{env, sync::Arc};

use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client;
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, Response, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
    routing::any,
};
use rclone_crypt::{Credential, Keys, NameCipher, RcloneCryptObject};
use rclone_crypt_aws::S3RangeSource;
use subtle::ConstantTimeEq;

#[derive(Clone)]
struct AppState {
    client: Client,
    bucket: String,
    prefix: String,
    keys: Keys,
    names: NameCipher,
    bearer_token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = required("S3_ENDPOINT")?;
    let region = required("S3_REGION")?;
    let bucket = required("S3_BUCKET")?;
    let password = Credential::Clear(required("RCLONE_CRYPT_PASSWORD")?);
    let salt = env::var("RCLONE_CRYPT_SALT").ok().map(Credential::Clear);
    let keys = Keys::derive(&password, salt.as_ref())?;

    let shared = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region))
        .endpoint_url(endpoint)
        .load()
        .await;
    let s3_config = aws_sdk_s3::config::Builder::from(&shared)
        .force_path_style(true)
        .build();
    let state = AppState {
        client: Client::from_conf(s3_config),
        bucket,
        prefix: env::var("S3_PREFIX")
            .unwrap_or_default()
            .trim_matches('/')
            .to_owned(),
        names: NameCipher::new(&keys),
        keys,
        bearer_token: env::var("PROXY_BEARER_TOKEN").ok(),
    };
    let listen = env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let app = Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .route("/{*path}", any(proxy))
        .with_state(state);
    eprintln!("listening on {listen}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    method: Method,
    headers: HeaderMap,
) -> Response<Body> {
    if !authorized(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if path.is_empty()
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let encrypted_path = match state.names.encrypt_path(&path) {
        Ok(path) => path,
        Err(_) => return StatusCode::URI_TOO_LONG.into_response(),
    };
    let key = if state.prefix.is_empty() {
        encrypted_path
    } else {
        format!("{}/{encrypted_path}", state.prefix)
    };
    let source = Arc::new(S3RangeSource::new(
        state.client.clone(),
        state.bucket.clone(),
        key,
    ));
    let object = match RcloneCryptObject::open(source, state.keys.clone()).await {
        Ok(object) => Arc::new(object),
        Err(rclone_crypt::Error::SourceNotFound(_)) => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(rclone_crypt::Error::Authentication | rclone_crypt::Error::BadMagic) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    let content_type = HeaderValue::from_str(mime.as_ref()).ok();
    let response = rclone_crypt_http::serve(object, &method, &headers, content_type).await;
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, Body::new(body))
}

fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = &state.bearer_token else {
        return true;
    };
    let expected_header = format!("Bearer {expected}");
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            // Constant-time comparison so a timing side channel cannot be used to
            // recover the token byte by byte. Length is still leaked, which is
            // acceptable for a fixed-format bearer header.
            value.as_bytes().ct_eq(expected_header.as_bytes()).into()
        })
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("missing {name}").into())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
