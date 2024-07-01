use regex::Regex;
use std::env;
use std::io::{self, BufRead, BufReader};
use std::net::TcpStream;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: regresshion-check <server_address>");
        std::process::exit(1);
    }

    let server_address: String = format!("{}:22", args[1]);

    let stream: TcpStream = TcpStream::connect_timeout(
        &server_address.parse().unwrap(),
        std::time::Duration::new(5, 0),
    )?;
    stream.set_read_timeout(Some(std::time::Duration::new(5, 0)))?;
    let mut reader: BufReader<&TcpStream> = BufReader::new(&stream);
    let mut version: String = String::new();

    reader.read_line(&mut version)?;
    version = version.trim().to_string();
    println!("SSH Version: {}", version);

    if is_vulnerable(&version) {
        eprintln!("{} vulnerable to CVE-2024-6387", args[1]);
        std::process::exit(1);
    } else {
        println!("{} NOT vulnerable to CVE-2024-6387", args[1]);
    }

    Ok(())
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
            let parser: Regex = Regex::new(r"([0-9]+)ubuntu([0-9.]+)").unwrap();
            if let Some(captured) = parser.captures(version) {
                let upstream_patch: i32 = captured[1].parse().unwrap();
                let ubuntu_patch: f32 = captured[2].parse::<f32>().unwrap_or(0.0);
                if (ssh_major == 8
                    && ssh_minor == 9
                    && ssh_patch >= 1
                    && upstream_patch >= 3
                    && ubuntu_patch >= 0.10)
                    || (ssh_major == 9
                        && ssh_minor == 3
                        && ssh_patch >= 1
                        && upstream_patch >= 1
                        && ubuntu_patch >= 3.6)
                    || (ssh_major == 9
                        && ssh_minor == 6
                        && ssh_patch >= 1
                        && upstream_patch == 3
                        && ubuntu_patch >= 13.3)
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
