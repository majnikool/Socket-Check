```markdown
# SSL Debugging and Troubleshooting Script

## Overview

This script is designed to help with debugging and troubleshooting SSL-related issues. It performs various network checks, captures traffic, analyzes packets, and retrieves SSL certificate information from a specified server.

## Features

- Captures network traffic to and from the target server.
- Analyzes the captured packets to identify SYN, SYN-ACK, RST, ICMP request, ICMP response, and SSL handshake packets.
- Checks network connectivity using `nmap`.
- Retrieves SSL certificate details, including the domain name (CN) and expiry date.

## Prerequisites

Before running the script, ensure you have the following binaries installed on your system:

- `nmap`
- `tshark` (part of the Wireshark suite)

## Installation

1. Clone the repository or download the script.

2. Install the required Python packages using the provided `requirements.txt` file:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the script with the following command:

```bash
python3 check3.py <target_ip> <target_port> <interface>
```

- `<target_ip>`: The IP address of the target server.
- `<target_port>`: The port number of the target server (typically 443 for HTTPS).
- `<interface>`: The network interface to use for capturing traffic (e.g., `ens224`).

### Example

```bash
python3 check3.py 172.20.28.17 443 ens224
```

## Output

The script will produce an output similar to the following:

```plaintext
*** Checking Network Connectivity with Nmap ***

Running Nmap to check if host is up...
<output from nmap>

Running Nmap with -Pn flag to skip host discovery...
<output from nmap>

Sending SYN packet...
Received SYN-ACK response.
Sending ICMP echo request...
Received ICMP echo reply.

Checking SSL certificate for 172.20.28.17:443...

Domain Name (CN): *.example.com
Expiry Date: 2025-02

Capturing traffic... Please wait.
Captured 40 packets

*** Summary ***
+----------------------------+----------+
| Test                       | Result   |
+============================+==========+
| Host Status (Normal Scan)  | up       |
+----------------------------+----------+
| Host Status (-Pn Scan)     | up       |
+----------------------------+----------+
| Port 443 Status (-Pn Scan) | open     |
+----------------------------+----------+
| SYN Packets                | Found    |
+----------------------------+----------+
| SYN-ACK Packets            | Found    |
+----------------------------+----------+
| RST Packets                | Found    |
+----------------------------+----------+
| ICMP Request Packets       | Found    |
+----------------------------+----------+
| ICMP Response Packets      | Found    |
+----------------------------+----------+
| SSL Handshake Packets      | Found    |
+----------------------------+----------+
| SSL Certificate Found      | Yes      |
+----------------------------+----------+
| SSL Certificate Details    | CN: *.example.com, Expiry: 2025-02 |
+----------------------------+----------+

Analysis: Host is up and responding normally.
```

## Notes

- Ensure you have the appropriate permissions to run `nmap` and `tshark` on your system.
- The script captures up to 200 packets or times out after 20 seconds. You can adjust these parameters as needed.
