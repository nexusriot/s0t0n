use clap::{Arg, Command};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use std::io::{Read};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task;

const TIMEOUT: u64 = 2;
const MAX_CONCURRENT_TASKS: usize = 100;

async fn scan_port(ip: Arc<String>, port: u16, semaphore: Arc<Semaphore>) {
    let _permit = semaphore.acquire().await.unwrap();

    let addr = format!("{}:{}", ip, port);
    let socket_addr: SocketAddr = match addr.parse() {
        Ok(addr) => addr,
        Err(_) => return,
    };

    let result = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(TIMEOUT));

    match result {
        Ok(mut stream) => {
            println!("Port {} is open", port);
            stream.set_read_timeout(Some(Duration::from_secs(TIMEOUT))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(TIMEOUT))).unwrap();
            
            let mut buffer = [0; 1024];
            match stream.read(&mut buffer) {
                Ok(_) => {
                    let banner = String::from_utf8_lossy(&buffer);
                    println!("Banner on port {}: {}", port, banner);
                }
                Err(_) => println!("Failed to read banner on port {}", port),
            }
        }
        Err(_) => {}
    }
}

#[tokio::main]
async fn main() {
    let matches = Command::new("S0t0n banner Scanner")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("Scans ports and grabs banners")
        .arg(
            Arg::new("ip")
                .short('i')
                .long("ip")
                .value_name("IP")
                .help("Sets the target IP address")
                .required(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("range")
                .short('r')
                .long("range")
                .value_name("RANGE")
                .help("Sets the port range to scan (e.g., 1-1024)")
                .required(true)
                .value_parser(clap::value_parser!(String)),
        )
        .get_matches();

    let ip = matches.get_one::<String>("ip").unwrap().to_string();
    let range = matches.get_one::<String>("range").unwrap();
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        eprintln!("Invalid range format. Use the format: start-end");
        return;
    }

    let start_port: u16 = match parts[0].parse() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("Invalid start port.");
            return;
        }
    };

    let end_port: u16 = match parts[1].parse() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("Invalid end port.");
            return;
        }
    };

    if start_port > end_port {
        eprintln!("Start port must be less than or equal to end port.");
        return;
    }

    let ip = Arc::new(ip);
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TASKS));
    
    let mut tasks = vec![];

    for port in start_port..=end_port {
        let ip_clone = Arc::clone(&ip);
        let semaphore_clone = Arc::clone(&semaphore);

        let task = task::spawn(scan_port(ip_clone, port, semaphore_clone));
        tasks.push(task);
    }

    for task in tasks {
        let _ = task.await;
    }
}