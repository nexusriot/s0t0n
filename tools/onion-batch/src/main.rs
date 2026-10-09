//! onion-batch — read a file of .onion (or clearnet) URLs, fetch each over a
//! single bootstrapped Tor client, and print an uptime/title/latency table.
//! A batch sibling of the onion_checker PoC. Authorized use only.

use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arti_client::config::BoolOrAuto;
use arti_client::{StreamPrefs, TorClient, TorClientConfig};
use http::uri::{Scheme, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::time::timeout;
use tor_rtcompat::Runtime;

const PER_REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_CONCURRENCY: usize = 8;

struct Report {
    url: String,
    status: String,
    title: String,
    latency: String,
}

fn extract_title(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_lowercase();
    if let Some(start) = lower.find("<title>") {
        if let Some(end) = lower[start..].find("</title>") {
            let raw = &text[start + 7..start + end];
            let title: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
            return title.chars().take(70).collect();
        }
    }
    "-".to_string()
}

async fn check<R: Runtime>(client: TorClient<R>, url: String) -> Report {
    let started = Instant::now();
    let result = timeout(PER_REQUEST_TIMEOUT, fetch(&client, &url)).await;
    let latency = format!("{} ms", started.elapsed().as_millis());
    match result {
        Ok(Ok((status, title))) => Report { url, status, title, latency },
        Ok(Err(e)) => Report { url, status: "ERR".into(), title: short_err(&e), latency },
        Err(_) => Report { url, status: "TIMEOUT".into(), title: "-".into(), latency },
    }
}

fn short_err(e: &anyhow::Error) -> String {
    let s = e.to_string();
    s.chars().take(60).collect()
}

async fn fetch<R: Runtime>(client: &TorClient<R>, url: &str) -> Result<(String, String)> {
    let uri = Uri::from_str(url)?;
    let host = uri.host().context("missing host in URI")?.to_string();
    let port = match (uri.port_u16(), uri.scheme()) {
        (Some(p), _) => p,
        (_, Some(s)) if *s == Scheme::HTTPS => 443,
        _ => 80,
    };

    let mut prefs = StreamPrefs::new();
    prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
    let stream = client
        .connect_with_prefs(format!("{host}:{port}"), &prefs)
        .await
        .context("tor connect failed")?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .header("Host", &host)
        .uri(&uri)
        .body(Empty::<Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    let status = resp.status().to_string();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, extract_title(&body)))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <urls.txt>", args[0]);
        eprintln!("  one URL per line, e.g. http://example.onion");
        std::process::exit(1);
    }

    let content = tokio::fs::read_to_string(&args[1])
        .await
        .with_context(|| format!("cannot read {}", args[1]))?;
    let urls: Vec<String> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();

    if urls.is_empty() {
        eprintln!("no URLs found in {}", args[1]);
        std::process::exit(1);
    }

    eprintln!("Bootstrapping Tor client (first run is slow)...");
    let client = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
    eprintln!("Checking {} URL(s)...\n", urls.len());

    // Bounded concurrency via buffered stream of cloned clients.
    use futures::stream::{self, StreamExt};
    let reports: Vec<Report> = stream::iter(urls.into_iter().map(|u| {
        let c = client.clone();
        async move { check(c, u).await }
    }))
    .buffer_unordered(MAX_CONCURRENCY)
    .collect()
    .await;

    println!("{:<45} {:<8} {:<10} {}", "URL", "STATUS", "LATENCY", "TITLE");
    println!("{}", "-".repeat(90));
    for r in &reports {
        let url: String = r.url.chars().take(44).collect();
        println!("{:<45} {:<8} {:<10} {}", url, r.status, r.latency, r.title);
    }
    Ok(())
}
