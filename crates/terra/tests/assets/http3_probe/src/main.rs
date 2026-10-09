//! HTTP/3 test fixture: a server, a compatibility client, and a verified-transfer timer.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, Bytes};
use http::{Method, Request, Response, Uri, header};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::RootCertStore;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject};
use tokio::task::JoinHandle;

const USAGE: &str = "usage: http3-probe server|client ADDRESS CERT_DIRECTORY | upload|download ADDRESS CERT_DIRECTORY BYTES";
const UPLOAD_ACKNOWLEDGMENT: &str = "terra-http3-upload-ok";
const HELLO: &str = "terra-http3-ok";
const PROTOCOL: &str = "HTTP/3.0";
const CHUNK_BYTES: usize = 64 * 1024;
const CLIENT_TIMEOUT: Duration = Duration::from_mins(5);

#[allow(clippy::cast_possible_truncation)]
fn pattern_byte(offset: u64) -> u8 {
    (offset % 256) as u8
}

fn fill_pattern(offset: u64, buffer: &mut [u8]) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = pattern_byte(offset + index as u64);
    }
}

/// Checks that a stream is exactly `expected` bytes of the pattern.
struct PatternVerifier {
    expected: u64,
    seen: u64,
}

impl PatternVerifier {
    fn new(expected: u64) -> Self {
        Self { expected, seen: 0 }
    }

    fn feed(&mut self, data: &[u8]) -> Result<()> {
        ensure!(
            self.seen + data.len() as u64 <= self.expected,
            "payload exceeds expected size"
        );
        for (index, &byte) in data.iter().enumerate() {
            let offset = self.seen + index as u64;
            ensure!(
                byte == pattern_byte(offset),
                "payload mismatch at byte {offset}"
            );
        }
        self.seen += data.len() as u64;
        Ok(())
    }

    fn finish(&self) -> Result<()> {
        ensure!(self.seen == self.expected, "incomplete payload");
        Ok(())
    }
}

fn parse_byte_count(value: &str) -> Result<u64> {
    match value.parse::<i64>() {
        Ok(size) if size > 0 => Ok(size.unsigned_abs()),
        _ => bail!("byte count must be a positive integer"),
    }
}

#[derive(Debug, PartialEq)]
enum Route {
    Hello,
    Echo,
    Upload(u64),
    Download(u64),
    Reject {
        status: u16,
        message: &'static str,
        allow: Option<&'static str>,
    },
}

fn route(method: &Method, uri: &Uri) -> Route {
    let (required, is_upload) = match uri.path() {
        "/upload" => (Method::POST, true),
        "/download" => (Method::GET, false),
        _ if method == Method::POST => return Route::Echo,
        _ => return Route::Hello,
    };
    if *method != required {
        let allow = if is_upload { "POST" } else { "GET" };
        return Route::Reject {
            status: 405,
            message: "incorrect method",
            allow: Some(allow),
        };
    }
    let size = uri
        .query()
        .and_then(|query| {
            query
                .split('&')
                .find_map(|pair| pair.strip_prefix("bytes="))
        })
        .map(parse_byte_count);
    match (size, is_upload) {
        (Some(Ok(size)), true) => Route::Upload(size),
        (Some(Ok(size)), false) => Route::Download(size),
        _ => Route::Reject {
            status: 400,
            message: "byte count must be a positive integer",
            allow: None,
        },
    }
}

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn respond_text(
    stream: &mut ServerStream,
    status: u16,
    allow: Option<&str>,
    body: &str,
) -> Result<()> {
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_LENGTH, body.len());
    if let Some(allow) = allow {
        response = response.header(header::ALLOW, allow);
    }
    stream.send_response(response.body(())?).await?;
    stream
        .send_data(Bytes::copy_from_slice(body.as_bytes()))
        .await?;
    stream.finish().await?;
    Ok(())
}

/// Reads the request to its end; dropping it unread makes quinn send `STOP_SENDING(0)`, failing the client's `finish`.
async fn drain_request(stream: &mut ServerStream) -> Result<()> {
    while stream.recv_data().await?.is_some() {}
    Ok(())
}

async fn verify_upload(stream: &mut ServerStream, size: u64) -> Result<()> {
    let mut verifier = PatternVerifier::new(size);
    while let Some(mut chunk) = stream.recv_data().await? {
        while chunk.has_remaining() {
            verifier.feed(chunk.chunk())?;
            chunk.advance(chunk.chunk().len());
        }
    }
    verifier.finish()
}

async fn serve_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) -> Result<()> {
    let (request, mut stream) = resolver.resolve_request().await?;
    match route(request.method(), request.uri()) {
        Route::Hello => {
            drain_request(&mut stream).await?;
            respond_text(&mut stream, 200, None, HELLO).await
        }
        Route::Reject {
            status,
            message,
            allow,
        } => {
            drain_request(&mut stream).await?;
            respond_text(&mut stream, status, allow, message).await
        }
        Route::Echo => {
            stream.send_response(Response::new(())).await?;
            while let Some(mut chunk) = stream.recv_data().await? {
                stream
                    .send_data(chunk.copy_to_bytes(chunk.remaining()))
                    .await?;
            }
            Ok(stream.finish().await?)
        }
        Route::Upload(size) => {
            let outcome = verify_upload(&mut stream, size).await;
            match outcome {
                Ok(()) => respond_text(&mut stream, 200, None, UPLOAD_ACKNOWLEDGMENT).await,
                Err(error) => respond_text(&mut stream, 400, None, &error.to_string()).await,
            }
        }
        Route::Download(size) => {
            drain_request(&mut stream).await?;
            let response = Response::builder()
                .header(header::CONTENT_LENGTH, size)
                .body(())?;
            stream.send_response(response).await?;
            let mut buffer = vec![0; CHUNK_BYTES];
            let mut offset = 0;
            while offset < size {
                let length = usize::try_from(size - offset)?.min(CHUNK_BYTES);
                fill_pattern(offset, &mut buffer[..length]);
                stream
                    .send_data(Bytes::copy_from_slice(&buffer[..length]))
                    .await?;
                offset += length as u64;
            }
            Ok(stream.finish().await?)
        }
    }
}

async fn serve_connection(incoming: quinn::Incoming) -> Result<()> {
    let connection = h3_quinn::Connection::new(incoming.await?);
    let mut connection = h3::server::Connection::new(connection).await?;
    while let Some(resolver) = connection.accept().await? {
        tokio::spawn(async move {
            if let Err(error) = serve_request(resolver).await {
                eprintln!("request failed: {error:#}");
            }
        });
    }
    Ok(())
}

/// Writes the certificate to `directory`, binds `address`, and records the bound address there.
fn bind_server(address: &str, directory: &Path) -> Result<quinn::Endpoint> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::hours(24);
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    std::fs::write(directory.join("certificate.pem"), certificate.pem())?;

    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let endpoint = quinn::Endpoint::server(config, address.parse::<SocketAddr>()?)?;
    std::fs::write(
        directory.join("address"),
        endpoint.local_addr()?.to_string(),
    )?;
    Ok(endpoint)
}

async fn serve(endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(error) = serve_connection(incoming).await {
                eprintln!("connection failed: {error:#}");
            }
        });
    }
}

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

struct Client {
    sender: Sender,
    address: String,
    _endpoint: quinn::Endpoint,
    driver: JoinHandle<()>,
}

impl Client {
    async fn connect(address: &str, directory: &Path) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        let pem = std::fs::read(directory.join("certificate.pem"))?;
        roots.add(CertificateDer::from_pem_slice(&pem).context("invalid fixture certificate")?)?;
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(tls)?,
        )));
        let connection = endpoint.connect(address.parse()?, "localhost")?.await?;
        let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection)).await?;
        let driver = tokio::spawn(async move {
            driver.wait_idle().await;
        });
        Ok(Self {
            sender,
            address: address.to_owned(),
            _endpoint: endpoint,
            driver,
        })
    }

    /// Sends `upload_len` bytes made by `fill`, requires a 200 response, and passes its body to `consume`.
    async fn fetch(
        &mut self,
        method: Method,
        path: &str,
        upload_len: u64,
        fill: impl Fn(u64, &mut [u8]),
        mut consume: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("https://{}{path}", self.address));
        if upload_len > 0 {
            request = request.header(header::CONTENT_LENGTH, upload_len);
        }
        let mut stream = self
            .sender
            .send_request(request.body(())?)
            .await
            .context("send request")?;
        let mut buffer = vec![0; CHUNK_BYTES];
        let mut offset = 0;
        while offset < upload_len {
            let length = usize::try_from(upload_len - offset)?.min(CHUNK_BYTES);
            fill(offset, &mut buffer[..length]);
            stream
                .send_data(Bytes::copy_from_slice(&buffer[..length]))
                .await
                .context("send body")?;
            offset += length as u64;
        }
        stream.finish().await.context("finish request")?;
        let response = stream.recv_response().await.context("receive response")?;
        ensure!(
            response.status() == 200,
            "HTTP/3 response mismatch: {}",
            response.status()
        );
        while let Some(mut chunk) = stream.recv_data().await.context("receive body")? {
            while chunk.has_remaining() {
                consume(chunk.chunk())?;
                chunk.advance(chunk.chunk().len());
            }
        }
        Ok(())
    }

    async fn fetch_exact(
        &mut self,
        method: Method,
        path: &str,
        sent: &[u8],
        expected: &[u8],
    ) -> Result<()> {
        let mut received = Vec::new();
        let sent_len = sent.len() as u64;
        let fill = |offset: u64, buffer: &mut [u8]| {
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            buffer.copy_from_slice(&sent[start..start + buffer.len()]);
        };
        self.fetch(method, path, sent_len, fill, |data| {
            received.extend_from_slice(data);
            Ok(())
        })
        .await?;
        ensure!(received == expected, "HTTP/3 response payload mismatch");
        Ok(())
    }
}

async fn run_client(address: &str, directory: &Path) -> Result<()> {
    let mut client = Client::connect(address, directory).await?;
    client
        .fetch_exact(Method::GET, "/", &[], HELLO.as_bytes())
        .await?;
    println!("{PROTOCOL} GET: {} verified bytes", HELLO.len());
    for size in [4096, 65536] {
        let payload = vec![0x5a; size];
        client
            .fetch_exact(Method::POST, "/", &payload, &payload)
            .await?;
        println!("{PROTOCOL} POST: {size} verified bytes");
    }
    client.driver.abort();
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
async fn run_transfer(mode: &str, address: &str, directory: &Path, size: u64) -> Result<()> {
    let mut client = Client::connect(address, directory).await?;
    client
        .fetch_exact(Method::GET, "/", &[], HELLO.as_bytes())
        .await?;
    let path = format!("/{mode}?bytes={size}");
    let started = Instant::now();
    if mode == "upload" {
        let mut acknowledgment = Vec::new();
        let sink = |data: &[u8]| {
            ensure!(
                acknowledgment.len() + data.len() <= UPLOAD_ACKNOWLEDGMENT.len(),
                "unexpected upload response"
            );
            acknowledgment.extend_from_slice(data);
            Ok(())
        };
        client
            .fetch(Method::POST, &path, size, fill_pattern, sink)
            .await?;
        ensure!(
            acknowledgment == UPLOAD_ACKNOWLEDGMENT.as_bytes(),
            "HTTP/3 response payload mismatch"
        );
    } else {
        let mut verifier = PatternVerifier::new(size);
        client
            .fetch(Method::GET, &path, 0, fill_pattern, |data| {
                verifier.feed(data)
            })
            .await?;
        verifier.finish()?;
    }
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::json!({
            "case": format!("http3_{mode}"),
            "bytes": size,
            "seconds": seconds,
            "mib_per_second": size as f64 / 1_048_576.0 / seconds,
            "protocol": PROTOCOL,
            "verified": true,
        })
    );
    client.driver.abort();
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["server", address, directory] => {
            serve(bind_server(address, Path::new(directory))?).await;
            Ok(())
        }
        ["client", address, directory] => {
            tokio::time::timeout(CLIENT_TIMEOUT, run_client(address, Path::new(directory))).await?
        }
        [mode @ ("upload" | "download"), address, directory, size] => {
            let size = parse_byte_count(size)?;
            tokio::time::timeout(
                CLIENT_TIMEOUT,
                run_transfer(mode, address, Path::new(directory), size),
            )
            .await?
        }
        _ => bail!(USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_matches_offset_modulo_256_at_every_chunk_size() {
        for chunk_size in [1, 255, 257, 65535, 65537] {
            let total = 2 * 65536 + 17;
            let mut buffer = vec![0; chunk_size];
            let mut verifier = PatternVerifier::new(total);
            let mut offset = 0;
            while offset < total {
                let length = usize::try_from(total - offset).unwrap().min(chunk_size);
                fill_pattern(offset, &mut buffer[..length]);
                verifier.feed(&buffer[..length]).unwrap();
                offset += length as u64;
            }
            verifier.finish().unwrap();
        }
        assert_eq!(pattern_byte(256 + 7), 7);
    }

    #[test]
    fn verifier_rejects_mismatch_short_and_extra_data() {
        assert!(PatternVerifier::new(2).feed(&[0, 0]).is_err());
        let mut short = PatternVerifier::new(2);
        short.feed(&[0]).unwrap();
        assert!(short.finish().is_err());
        assert!(PatternVerifier::new(1).feed(&[0, 1]).is_err());
        let mut extra = PatternVerifier::new(1);
        extra.feed(&[0]).unwrap();
        assert!(extra.feed(&[1]).is_err());
    }

    #[test]
    fn byte_count_must_be_a_positive_integer() {
        assert_eq!(parse_byte_count("1").unwrap(), 1);
        assert_eq!(
            parse_byte_count("9223372036854775807").unwrap(),
            i64::MAX.unsigned_abs()
        );
        for bad in ["", "0", "-1", "x", "1.5", "9223372036854775808"] {
            assert!(parse_byte_count(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn routes_follow_the_wire_contract() {
        let get = |method: &Method, uri: &str| route(method, &uri.parse().unwrap());
        assert_eq!(get(&Method::GET, "/"), Route::Hello);
        assert_eq!(get(&Method::POST, "/anything"), Route::Echo);
        assert_eq!(get(&Method::POST, "/upload?bytes=5"), Route::Upload(5));
        assert_eq!(get(&Method::GET, "/download?bytes=5"), Route::Download(5));
        for (method, uri, status) in [
            (&Method::GET, "/upload?bytes=1", 405),
            (&Method::POST, "/download?bytes=1", 405),
            (&Method::GET, "/download", 400),
            (&Method::GET, "/download?bytes=-1", 400),
            (&Method::GET, "/download?bytes=0", 400),
            (&Method::POST, "/upload?bytes=x", 400),
        ] {
            assert!(
                matches!(get(method, uri), Route::Reject { status: s, .. } if s == status),
                "{uri}"
            );
        }
        assert!(matches!(
            get(&Method::GET, "/upload?bytes=1"),
            Route::Reject {
                allow: Some("POST"),
                ..
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_and_server_agree_over_loopback() {
        let directory =
            std::env::temp_dir().join(format!("http3-probe-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        tokio::spawn(serve(bind_server("127.0.0.1:0", &directory).unwrap()));
        let address = std::fs::read_to_string(directory.join("address")).unwrap();
        run_client(&address, &directory).await.unwrap();
        for mode in ["upload", "download"] {
            run_transfer(mode, &address, &directory, 2 * 65536 + 17)
                .await
                .unwrap();
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
