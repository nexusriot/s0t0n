use std::env;
use anyhow::Context;
use arti_client::{StreamPrefs, TorClient, TorClientConfig};
use arti_client::config::BoolOrAuto;
use http::{uri::Scheme, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{Bytes},
    Request,
};
use hyper_util::rt::TokioIo;
use std::str::FromStr;
use tokio::io::{self, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <uri>", args[0]);
        std::process::exit(1);
    }
    let uri = &args[1];

    println!("Setting up TOR client config...");
    let client_config = TorClientConfig::default();

    println!("Creating bootstrapped tor client...");
    let client = TorClient::create_bootstrapped(client_config).await?;

    let uri: Uri = Uri::from_str(uri)?;
    let host = uri.host().context("Missing host in URI")?;
    let port = match (uri.port_u16(), uri.scheme()) {
        (Some(port), _) => port,
        (_, Some(scheme)) if *scheme == Scheme::HTTPS => 443,
        _ => 80,
    };

    println!("Connecting tor client to '{}:{}'", host, port);

    // need to use stram prefs for connection to onion service
    let mut prefs: StreamPrefs = StreamPrefs::new();
    prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
    
    let stream = client
        .connect_with_prefs(format!("{}:{}", host, port), &prefs)
        .await
        .context("Failed to connect tor client to specified address")?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    println!("Sending GET request...");
    let request = Request::builder()
        .method("GET")
        .header("Host", host)
        .uri(uri)
        .body(Empty::<Bytes>::new())?;
    let mut resp = sender.send_request(request).await?;

    println!("Response status: {}", resp.status());
    println!("Response headers: {:#?}", resp.headers());
    println!("Response body:");
    while let Some(next) = resp.frame().await {
        let frame = next?;
        if let Some(chunk) = frame.data_ref() {
            io::stdout().write_all(&chunk).await?;
        }
    }
    println!();

    Ok(())
}