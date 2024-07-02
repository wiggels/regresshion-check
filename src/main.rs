use regex::Regex;
use serde::Serialize;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use cidr::Ipv4Cidr;
use tokio::task;
use tokio::time::{timeout, Duration};
use tokio::io::AsyncBufReadExt;
use dns_lookup::lookup_addr;

#[derive(Serialize, Default)]
struct ScanResult {
    unknown: usize,
    patched: usize,
    vulnerable: usize,
    vulnerable_ips: Vec<IPInfo>,
}

#[derive(Serialize)]
struct IPInfo {
    ip: String,
    hostname: String,
    version: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: regresshion-check --individual <server_address> | --file <file_path>");
        std::process::exit(1);
    }

    let mode: &String = &args[1];
    let scan_result: Arc<Mutex<ScanResult>> = Arc::new(Mutex::new(ScanResult::default()));

    match mode.as_str() {
        "--individual" => {
            let server_address: Arc<String> = Arc::new(args[2].clone());
            scan_ip(server_address, scan_result.clone()).await;
        }
        "--file" => {
            let file_path: &String = &args[2];
            let _ = scan_file(file_path, scan_result.clone()).await;
        }
        _ => {
            eprintln!("Invalid mode. Use --individual or --file.");
            std::process::exit(1);
        }
    }

    let mut scan_result: std::sync::MutexGuard<ScanResult> = scan_result.lock().unwrap();
    scan_result.vulnerable_ips.sort_by(|a: &IPInfo, b: &IPInfo| a.ip.cmp(&b.ip)); // Sorting the vulnerable IPs by IP address
    let json_result: String = serde_json::to_string_pretty(&*scan_result).unwrap();
    println!("{}", json_result);

    Ok(())
}

async fn scan_ip(ip: Arc<String>, scan_result: Arc<Mutex<ScanResult>>) {
    let server_address: String = format!("{}:22", ip);

    let socket_addr: SocketAddr = match server_address.parse() {
        Ok(addr) => addr,
        Err(_) => {
            let mut result: std::sync::MutexGuard<ScanResult> = scan_result.lock().unwrap();
            result.unknown += 1;
            return;
        }
    };

    let stream: tokio::net::TcpStream = match timeout(
        Duration::new(2, 0),
        tokio::net::TcpStream::connect(&socket_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => {
            let mut result: std::sync::MutexGuard<ScanResult> = scan_result.lock().unwrap();
            result.unknown += 1;
            return;
        }
    };

    let mut reader: tokio::io::BufReader<tokio::net::TcpStream> = tokio::io::BufReader::new(stream);
    let mut version: String = String::new();

    match timeout(Duration::new(1, 0), reader.read_line(&mut version)).await {
        Ok(Ok(_)) => {
            version = version.trim().to_string();
            let hostname: String = get_hostname(&socket_addr.ip()).unwrap_or_else(|| "Unknown".to_string());
            if is_vulnerable(&version) {
                let mut result: std::sync::MutexGuard<ScanResult> = scan_result.lock().unwrap();
                result.vulnerable += 1;
                result.vulnerable_ips.push(IPInfo {
                    ip: ip.to_string(),
                    hostname,
                    version: version.clone(),
                });
            } else {
                let mut result: std::sync::MutexGuard<ScanResult> = scan_result.lock().unwrap();
                result.patched += 1;
            }
        }
        _ => {
            let mut result: std::sync::MutexGuard<ScanResult> = scan_result.lock().unwrap();
            result.unknown += 1;
        }
    }
}

async fn scan_file(file_path: &str, scan_result: Arc<Mutex<ScanResult>>) -> io::Result<()> {
    let file: File = File::open(file_path)?;
    let reader: BufReader<File> = BufReader::new(file);
    let mut ips: Vec<Arc<String>> = Vec::new();

    for line in reader.lines() {
        let line: String = line?.trim().to_string();
        if line.is_empty() {
            continue;
        }
        if line.contains('/') {
            let cidr: Ipv4Cidr = Ipv4Cidr::from_str(&line).unwrap();
            for ip in cidr.iter().addresses() {
                let ip_str: String = ip.to_string();
                ips.push(Arc::new(ip_str));
            }
        } else if let Ok(ip) = IpAddr::from_str(&line) {
            ips.push(Arc::new(ip.to_string()));
        }
    }

    let mut handles: Vec<task::JoinHandle<()>> = vec![];
    for ip in ips {
        let handle: task::JoinHandle<()> = task::spawn(scan_ip(ip.clone(), scan_result.clone()));
        handles.push(handle);
        if handles.len() == 200 {
            for handle in handles {
                handle.await.unwrap();
            }
            handles = vec![];
        }
    }

    // Process any remaining handles if less than 200 IPs
    for handle in handles {
        handle.await.unwrap();
    }

    Ok(())
}

fn get_hostname(ip: &IpAddr) -> Option<String> {
    match lookup_addr(ip) {
        Ok(hostname) => Some(hostname),
        Err(_) => None,
    }
}

fn is_vulnerable(version: &str) -> bool {
    let parser: Regex = Regex::new(r"OpenSSH_([0-9]+)\.([0-9]+)p([0-9]+)").unwrap();
    if let Some(captured) = parser.captures(version) {
        let ssh_major: i32 = captured[1].parse().unwrap();
        let ssh_minor: i32 = captured[2].parse().unwrap();
        let ssh_patch: i32 = captured[3].parse().unwrap();

        // Check for versions earlier than 4.4p1
        if ssh_major < 4 || (ssh_major == 4 && (ssh_minor < 4 || (ssh_minor == 4 && ssh_patch < 1)))
        {
            return true;
        }

        if version.contains("Debian") {
            let parser: Regex = Regex::new(r"deb([0-9]+)u([0-9]+)").unwrap();
            if let Some(captured) = parser.captures(version) {
                let os_release: i32 = captured[1].parse().unwrap();
                let os_patch: i32 = captured[2].parse().unwrap();
                if (os_release == 12
                    && ssh_major == 9
                    && ssh_minor == 2
                    && ssh_patch >= 1
                    && os_patch >= 3)
                    || (os_release == 11
                        && ssh_major == 8
                        && ssh_minor == 4
                        && ssh_patch >= 1
                        && os_patch >= 3)
                {
                    return false;
                }
            }
        }

        if version.contains("Ubuntu") {
            let parser: Regex = Regex::new(r"([0-9]+)ubuntu([0-9]+)\.?([0-9]+)?").unwrap();
            if let Some(captured) = parser.captures(version) {
                let upstream_patch: i32 = captured[1].parse().unwrap();
                let ubuntu_patch: i32 = captured[2].parse().unwrap();
                let ubuntu_subpatch: i32 = captured.get(3).map_or(0, |m| m.as_str().parse().unwrap_or(0));
                if (ssh_major == 8
                    && ssh_minor == 9
                    && ssh_patch >= 1
                    && upstream_patch >= 3
                    && ubuntu_patch >= 10)
                    || (ssh_major == 9
                        && ssh_minor == 3
                        && ssh_patch >= 1
                        && upstream_patch >= 1
                        && ubuntu_patch >= 6)
                    || (ssh_major == 9
                        && ssh_minor == 6
                        && ssh_patch >= 1
                        && upstream_patch == 3
                        && ubuntu_patch >= 13
                        && ubuntu_subpatch >= 3)
                {
                    return false;
                }
            }
        }

        // Check for versions from 8.5p1 up to, but not including, 9.8p1
        if (ssh_major == 8 && ssh_minor == 5 && ssh_patch >= 1)
            || (ssh_major == 8 && ssh_minor > 5)
            || (ssh_major == 9 && ssh_minor < 8)
            || (ssh_major == 9 && ssh_minor == 8 && ssh_patch < 1)
        {
            return true;
        }

        return false;
    }

    false
}
