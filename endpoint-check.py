#python3 script.py 172.20.28.17 443 ens224

import os
import sys
import threading
import time
from scapy.all import *
from colorama import Fore, Style, init
from tabulate import tabulate
import socket
import ssl
import asn1crypto.x509
from datetime import datetime

init(autoreset=True)

# Check if the script is run with the correct number of arguments
if len(sys.argv) != 4:
    print(f"{Fore.RED}Usage: python3 {sys.argv[0]} <target_ip> <target_port> <interface>{Style.RESET_ALL}")
    sys.exit(1)

# Define the target IP, port, and network interface from command-line arguments
target_ip = sys.argv[1]
target_port = int(sys.argv[2])
interface = sys.argv[3]
capture_file = "capture.pcap"

def capture_traffic():
    print(f"{Fore.CYAN}Capturing traffic on interface {interface}...{Style.RESET_ALL}")
    packets = sniff(iface=interface, filter=f"host {target_ip}", count=200, timeout=20)
    wrpcap(capture_file, packets)
    print(f"Captured {len(packets)} packets")
    print(f"{Fore.GREEN}Capture file {capture_file} is saved in the script execution directory.{Style.RESET_ALL}")
    return packets

def analyze_capture():
    results = {
        "SYN Packets": "No SYN packets found.",
        "SYN-ACK Packets": "No SYN-ACK packets found.",
        "RST Packets": "No RST packets found.",
        "ICMP Request Packets": "No ICMP request packets found.",
        "ICMP Response Packets": "No ICMP response packets found.",
        "SSL Handshake Packets": "No SSL handshake packets found."
    }

    tshark_cmd = lambda filter: f"tshark -r {capture_file} -Y '{filter}' -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags -e ssl.handshake.type -e frame.time_relative 2>/dev/null"

    # Filter SYN packets
    syn_output = os.popen(tshark_cmd("tcp.flags.syn == 1 && tcp.flags.ack == 0")).read()
    if syn_output:
        results["SYN Packets"] = syn_output.strip().split("\n")

    # Filter SYN-ACK packets
    syn_ack_output = os.popen(tshark_cmd("tcp.flags.syn == 1 && tcp.flags.ack == 1")).read()
    if syn_ack_output:
        results["SYN-ACK Packets"] = syn_ack_output.strip().split("\n")

    # Filter RST packets
    rst_output = os.popen(tshark_cmd("tcp.flags.reset == 1")).read()
    if rst_output:
        results["RST Packets"] = rst_output.strip().split("\n")

    # Filter ICMP request packets
    icmp_req_output = os.popen(tshark_cmd("icmp.type == 8")).read()
    if icmp_req_output:
        results["ICMP Request Packets"] = icmp_req_output.strip().split("\n")

    # Filter ICMP response packets
    icmp_resp_output = os.popen(tshark_cmd("icmp.type == 0")).read()
    if icmp_resp_output:
        results["ICMP Response Packets"] = icmp_resp_output.strip().split("\n")

    # Filter SSL handshake packets
    ssl_handshake_output = os.popen(tshark_cmd("ssl.handshake.type")).read()
    if ssl_handshake_output:
        results["SSL Handshake Packets"] = ssl_handshake_output.strip().split("\n")

    return results

def send_syn_packet():
    print(f"{Fore.CYAN}Sending SYN packet...{Style.RESET_ALL}")
    syn_packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
    response = sr1(syn_packet, timeout=5, verbose=0)
    if response:
        print("Received SYN-ACK response.")
    else:
        print("No response from target.")

def send_icmp_packet():
    print(f"{Fore.CYAN}Sending ICMP echo request...{Style.RESET_ALL}")
    icmp_packet = IP(dst=target_ip)/ICMP()
    response = sr1(icmp_packet, timeout=5, verbose=0)
    if response:
        print("Received ICMP echo reply.")
    else:
        print("No ICMP response from target.")

def check_network_connectivity():
    print(f"\n*** {Fore.CYAN}Checking Network Connectivity with Nmap{Style.RESET_ALL} ***\n")

    # Use nmap with the same parameters as the manual command
    print("Running Nmap to check if host is up...")
    nmap_output = os.popen(f"nmap -sT -p {target_port} {target_ip}").read()
    print(nmap_output)

    host_status = "down"
    if "1 host up" in nmap_output:
        host_status = "up"
    elif "Host seems down" in nmap_output:
        host_status = "seems down"

    # Run Nmap with -Pn flag
    print(f"\n{Fore.CYAN}Running Nmap with -Pn flag to skip host discovery...{Style.RESET_ALL}")
    nmap_pn_output = os.popen(f"nmap -Pn -p {target_port} {target_ip}").read()
    print(nmap_pn_output)

    pn_status = "down"
    port_status = "unknown"
    if "1 host up" in nmap_pn_output:
        pn_status = "up"
        if f"{target_port}/tcp filtered" in nmap_pn_output:
            port_status = "filtered"
        elif f"{target_port}/tcp open" in nmap_pn_output:
            port_status = "open"
        elif f"{target_port}/tcp closed" in nmap_pn_output:
            port_status = "closed"

    return host_status, pn_status, port_status

def get_domain_and_expiry(cert):
    cert = asn1crypto.x509.Certificate.load(cert)
    subject = cert.subject.native
    common_name = subject.get('common_name', None)
    expiry_date = cert['tbs_certificate']['validity']['not_after'].native
    formatted_expiry_date = expiry_date.strftime("%Y-%m")
    return common_name, formatted_expiry_date

def check_ssl_certificate(ip, port):
    print(f"\n{Fore.CYAN}Checking SSL certificate for {ip}:{port}...{Style.RESET_ALL}")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    domain, expiry_date = get_domain_and_expiry(cert_bin)
                    cert_info = {
                        "Domain Name (CN)": domain,
                        "Expiry Date": expiry_date
                    }
                    print("\nDomain Name (CN):", domain)
                    print("Expiry Date:", expiry_date)
                    return cert_info
                else:
                    print("No certificate received in binary form.")
                    return None

    except ssl.SSLError as e:
        print(f"SSL error occurred: {e}")
        return None
    except socket.timeout:
        print("SSL certificate check timed out.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# Start capturing traffic in a separate thread
capture_thread = threading.Thread(target=capture_traffic)
capture_thread.start()

# Allow some time for the capture to start
time.sleep(2)

# Check network connectivity with Nmap
host_status, pn_status, port_status = check_network_connectivity()

# Send the SYN packet
send_syn_packet()

# Send ICMP echo request
send_icmp_packet()

# Initiate SSL handshake and check SSL certificate
cert_info = check_ssl_certificate(target_ip, target_port)

# Informative message about capturing traffic
print(f"{Fore.CYAN}Capturing traffic... Please wait.{Style.RESET_ALL}")

# Wait for the capture to finish
capture_thread.join()

# Analyze the captured packets using Tshark
results = analyze_capture()

# Summarize results
syn_found = "Found" if results["SYN Packets"] != "No SYN packets found." else "Not Found"
syn_ack_found = "Found" if results["SYN-ACK Packets"] != "No SYN-ACK packets found." else "Not Found"
rst_found = "Found" if results["RST Packets"] != "No RST packets found." else "Not Found"
icmp_req_found = "Found" if results["ICMP Request Packets"] != "No ICMP request packets found." else "Not Found"
icmp_resp_found = "Found" if results["ICMP Response Packets"] != "No ICMP response packets found." else "Not Found"
ssl_handshake_found = "Found" if results["SSL Handshake Packets"] != "No SSL handshake packets found." else "Not Found"
cert_found = "Yes" if cert_info else "No"
cert_details = f"CN: {cert_info['Domain Name (CN)']}, Expiry: {cert_info['Expiry Date']}" if cert_info else "No certificate information available"

summary = [
    ["Host Status (Normal Scan)", host_status],
    ["Host Status (-Pn Scan)", pn_status],
    ["Port 443 Status (-Pn Scan)", port_status],
    ["SYN Packets", syn_found],
    ["SYN-ACK Packets", syn_ack_found],
    ["RST Packets", rst_found],
    ["ICMP Request Packets", icmp_req_found],
    ["ICMP Response Packets", icmp_resp_found],
    ["SSL Handshake Packets", ssl_handshake_found],
    ["SSL Certificate Found", cert_found],
    ["SSL Certificate Details", cert_details]
]

print(f"\n{Fore.GREEN}*** Summary ***{Style.RESET_ALL}")
print(tabulate(summary, headers=["Test", "Result"], tablefmt="grid"))

# Analysis based on summary
analysis = "\n" + Fore.YELLOW + "Analysis: " + Style.RESET_ALL
if host_status == "seems down" and pn_status == "up":
    analysis += "Host seems down in normal scan but is up in -Pn scan. This indicates that ping (ICMP) is blocked, but the server is up.\n"
    if port_status == "filtered":
        analysis += f"{Fore.YELLOW}Port 443 is filtered, indicating it is likely blocked by a firewall.{Style.RESET_ALL}\n"
    elif port_status == "open":
        analysis += f"{Fore.GREEN}Port 443 is open and the service should be accessible, although ICMP is blocked.{Style.RESET_ALL}\n"
    elif port_status == "closed":
        analysis += f"{Fore.RED}Port 443 is closed, indicating no service is running on this port.{Style.RESET_ALL}\n"
elif host_status == "down" and pn_status == "down":
    analysis += f"{Fore.RED}Host is reported as down by both Nmap scans. It might be offline or completely blocking our probes.{Style.RESET_ALL}\n"
elif host_status == "up" or pn_status == "up":
    if port_status == "closed":
        analysis += f"{Fore.YELLOW}Host is up, but port 443 is closed. This means the port is not blocked, but no service is running on it.{Style.RESET_ALL}\n"
    elif syn_ack_found == "Not Found":
        analysis += f"{Fore.YELLOW}Host is up, but no SYN-ACK responses were captured. This indicates potential issues with TCP connections or firewall blocking.{Style.RESET_ALL}\n"
    else:
        analysis += f"{Fore.GREEN}Host is up and responding normally.{Style.RESET_ALL}\n"
else:
    analysis += f"{Fore.RED}Host status is inconclusive based on the scans and captured packets.{Style.RESET_ALL}\n"

print(analysis)
