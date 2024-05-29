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
    let ip = Arc::new("127.0.0.1".to_string()); // Replace with the target IP
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TASKS));
    
    let mut tasks = vec![];

    for port in 1..1024 {
        let ip_clone = Arc::clone(&ip);
        let semaphore_clone = Arc::clone(&semaphore);

        let task = task::spawn(scan_port(ip_clone, port, semaphore_clone));
        tasks.push(task);
    }

    for task in tasks {
        let _ = task.await;
    }
}
