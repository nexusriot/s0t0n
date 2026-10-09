use netutil::Cidr;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <CIDR> [--all]", args[0]);
        eprintln!("  Prints usable host addresses, one per line.");
        eprintln!("  --all  also include network and broadcast addresses.");
        return ExitCode::from(1);
    }

    let all = args.iter().any(|a| a == "--all");
    let cidr = match Cidr::parse(&args[1]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    if all {
        for ip in cidr.addresses() {
            println!("{ip}");
        }
    } else {
        for ip in cidr.hosts() {
            println!("{ip}");
        }
    }
    ExitCode::SUCCESS
}
