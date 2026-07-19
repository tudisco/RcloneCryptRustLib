#![forbid(unsafe_code)]

use std::{convert::Infallible, sync::Arc};

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{
    HeaderMap, HeaderValue, Method, Response, StatusCode,
    header::{ACCEPT_RANGES, ALLOW, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE},
};
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use rclone_crypt::{RangeSource, RcloneCryptObject};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

pub type ProxyBody = UnsyncBoxBody<Bytes, std::io::Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn len(self) -> u64 {
        self.end - self.start
    }

    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RangeError {
    Malformed,
    MultipleUnsupported,
    Unsatisfiable,
}

pub fn parse_range(value: &str, size: u64) -> Result<ByteRange, RangeError> {
    let value = value.strip_prefix("bytes=").ok_or(RangeError::Malformed)?;
    if value.contains(',') {
        return Err(RangeError::MultipleUnsupported);
    }
    let (start, end) = value.split_once('-').ok_or(RangeError::Malformed)?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| RangeError::Malformed)?;
        if suffix == 0 || size == 0 {
            return Err(RangeError::Unsatisfiable);
        }
        return Ok(ByteRange {
            start: size.saturating_sub(suffix),
            end: size,
        });
    }
    let start = start.parse::<u64>().map_err(|_| RangeError::Malformed)?;
    if start >= size {
        return Err(RangeError::Unsatisfiable);
    }
    let end = if end.is_empty() {
        size
    } else {
        end.parse::<u64>()
            .map_err(|_| RangeError::Malformed)?
            .saturating_add(1)
            .min(size)
    };
    if end <= start {
        return Err(RangeError::Unsatisfiable);
    }
    Ok(ByteRange { start, end })
}

pub async fn serve<S: RangeSource + 'static>(
    object: Arc<RcloneCryptObject<S>>,
    method: &Method,
    request_headers: &HeaderMap,
    content_type: Option<HeaderValue>,
) -> Response<ProxyBody> {
    if method != Method::GET && method != Method::HEAD {
        let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED, 0, None);
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    let size = object.plaintext_len();
    let requested = match (method == Method::GET)
        .then(|| request_headers.get(RANGE))
        .flatten()
    {
        None => None,
        Some(value) => {
            let Ok(value) = value.to_str() else {
                return empty_response(StatusCode::BAD_REQUEST, 0, None);
            };
            match parse_range(value, size) {
                Ok(range) => Some(range),
                Err(RangeError::Unsatisfiable) => {
                    return range_not_satisfiable(size);
                }
                Err(_) => return empty_response(StatusCode::BAD_REQUEST, 0, None),
            }
        }
    };
    let range = requested.unwrap_or(ByteRange {
        start: 0,
        end: size,
    });
    let status = if requested.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };

    if method == Method::HEAD {
        return response(
            status,
            empty_body(),
            range.len(),
            requested.map(|_| (range, size)),
            content_type,
        );
    }

    // Do not turn a tiny client range into the reader's default 1 MiB read-ahead.
    // Authentication still expands this to the containing 64 KiB rclone chunk.
    let mut reader = object
        .reader()
        .with_fetch_size(range.len().min(1024 * 1024))
        .with_prefetch(requested.is_none());
    if reader
        .seek(std::io::SeekFrom::Start(range.start))
        .await
        .is_err()
    {
        return empty_response(StatusCode::INTERNAL_SERVER_ERROR, 0, None);
    }
    let stream = ReaderStream::new(reader.take(range.len())).map_ok(http_body::Frame::data);
    let body = StreamBody::new(stream).boxed_unsync();
    response(
        status,
        body,
        range.len(),
        requested.map(|_| (range, size)),
        content_type,
    )
}

fn response(
    status: StatusCode,
    body: ProxyBody,
    length: u64,
    content_range: Option<(ByteRange, u64)>,
    content_type: Option<HeaderValue>,
) -> Response<ProxyBody> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
    if let Some((range, size)) = content_range {
        let value = format!("bytes {}-{}/{}", range.start, range.end - 1, size);
        headers.insert(CONTENT_RANGE, HeaderValue::from_str(&value).unwrap());
    }
    if let Some(content_type) = content_type {
        headers.insert(CONTENT_TYPE, content_type);
    }
    response
}

fn empty_response(
    status: StatusCode,
    length: u64,
    content_range: Option<(ByteRange, u64)>,
) -> Response<ProxyBody> {
    response(status, empty_body(), length, content_range, None)
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|error: Infallible| match error {})
        .boxed_unsync()
}

fn range_not_satisfiable(size: u64) -> Response<ProxyBody> {
    let mut response = empty_response(StatusCode::RANGE_NOT_SATISFIABLE, 0, None);
    response.headers_mut().insert(
        CONTENT_RANGE,
        HeaderValue::from_str(&format!("bytes */{size}")).unwrap(),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use rclone_crypt::{Credential, Keys, MemorySource, encrypt_to};

    #[test]
    fn parses_http_ranges() {
        assert_eq!(
            parse_range("bytes=10-19", 100),
            Ok(ByteRange { start: 10, end: 20 })
        );
        assert_eq!(
            parse_range("bytes=90-", 100),
            Ok(ByteRange {
                start: 90,
                end: 100
            })
        );
        assert_eq!(
            parse_range("bytes=-10", 100),
            Ok(ByteRange {
                start: 90,
                end: 100
            })
        );
        assert_eq!(
            parse_range("bytes=100-", 100),
            Err(RangeError::Unsatisfiable)
        );
        assert_eq!(
            parse_range("bytes=0-1,4-5", 100),
            Err(RangeError::MultipleUnsupported)
        );
    }

    #[tokio::test]
    async fn serves_head_and_unsatisfiable_range() {
        let mut encrypted = b"RCLONE\0\0".to_vec();
        encrypted.extend_from_slice(&[0_u8; 24]);
        let keys = Keys::derive(&Credential::Clear(String::new()), None).unwrap();
        let object = Arc::new(
            RcloneCryptObject::open(Arc::new(MemorySource::new(encrypted)), keys)
                .await
                .unwrap(),
        );

        let response = serve(
            Arc::clone(&object),
            &Method::HEAD,
            &HeaderMap::new(),
            Some(HeaderValue::from_static("video/mp4")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_LENGTH], "0");
        assert_eq!(response.headers()[ACCEPT_RANGES], "bytes");
        assert_eq!(response.headers()[CONTENT_TYPE], "video/mp4");

        let mut headers = HeaderMap::new();
        headers.insert(RANGE, HeaderValue::from_static("bytes=0-"));
        let response = serve(object, &Method::GET, &headers, None).await;
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.headers()[CONTENT_RANGE], "bytes */0");
    }

    #[tokio::test]
    async fn serves_authenticated_cross_chunk_partial_content() {
        let plaintext: Vec<u8> = (0..100_000).map(|index| (index % 251) as u8).collect();
        let keys = Keys::derive(&Credential::Clear(String::new()), None).unwrap();
        let mut reader = std::io::Cursor::new(plaintext.clone());
        let mut encrypted = Vec::new();
        encrypt_to(&mut reader, &mut encrypted, &keys)
            .await
            .unwrap();
        let object = Arc::new(
            RcloneCryptObject::open(Arc::new(MemorySource::new(encrypted)), keys)
                .await
                .unwrap(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, HeaderValue::from_static("bytes=65530-65545"));
        let response = serve(object, &Method::GET, &headers, None).await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.headers()[CONTENT_RANGE],
            "bytes 65530-65545/100000"
        );
        assert_eq!(response.headers()[CONTENT_LENGTH], "16");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], &plaintext[65_530..65_546]);
    }
}
