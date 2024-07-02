# regresshion-check

`regresshion-check` is a Rust CLI tool to check SSH servers for vulnerability to CVE-2024-6387. It takes in a single IP or multiple IPs/CIDRs separated by newlines in a file. It includes the reverse DNS lookup and version string with any IPs detected as vulnerable.

(IPs listed in readme are examples only -- do not use)

## Prerequisites

- Rust and Cargo installed. You can install Rust and Cargo using [rustup](https://rustup.rs/).

## Building the Application

1. Clone the repository:
    ```sh
    git clone git@github.com:wiggels/regresshion-check.git
    cd regresshion-check
    ```

2. Build the application:
    ```sh
    cargo build --release
    ```

## Usage

### Scan a Single IP Address

To scan a single IP address, use the `--individual` option followed by the IP address:

```sh
regresshion-check --individual <ip-address>
```

Example usage:
```sh
regresshion-check --individual 215.227.162.32
```

### Scan Multiple IP Addresses from a File

To scan multiple IP addresses listed in a file, use the `--file` option followed by the input file:

Example file contents:
```
215.227.64.0/24
215.227.162.32
```

Example usage:
```sh
regresshion-check --file /path/to/file/here.txt
```

### Scanning Batch Size

The scanning job batches based on the current ulimit size minus a buffer of 64. If you would like this application to run faster when doing larger CIDRs/lists, raise the ulimit. Example: `ulimit -n 8192`

### Example Output
```
{
  "unknown": 226,
  "patched": 29,
  "vulnerable": 2,
  "vulnerable_ips": [
    {
      "ip": "215.227.162.32",
      "hostname": "some.server.somewhere.com",
      "version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7"
    },
    {
      "ip": "215.227.64.156",
      "hostname": "another.server.somewhere.com",
      "version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7"
    }
  ]
}
```