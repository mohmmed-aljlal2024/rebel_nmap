#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# utils.py - Core Utilities Module

import socket
import re
import ipaddress
import json
import os
import platform
import random
import subprocess
from datetime import datetime

class Color:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    @staticmethod
    def red(text):
        return f"{Color.RED}{text}{Color.END}"

    @staticmethod
    def green(text):
        return f"{Color.GREEN}{text}{Color.END}"

    @staticmethod
    def yellow(text):
        return f"{Color.YELLOW}{text}{Color.END}"

    @staticmethod
    def blue(text):
        return f"{Color.BLUE}{text}{Color.END}"

    @staticmethod
    def magenta(text):
        return f"{Color.MAGENTA}{text}{Color.END}"

    @staticmethod
    def cyan(text):
        return f"{Color.CYAN}{text}{Color.END}"

    @staticmethod
    def bold(text):
        return f"{Color.BOLD}{text}{Color.END}"

def dns_lookup(hostname):
    """Resolve hostname to IP address with caching"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def reverse_dns(ip):
    """Perform reverse DNS lookup with error handling"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "NXDOMAIN"

def cidr_to_ips(cidr):
    """Convert CIDR notation to list of IP addresses"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []

def parse_ports(port_str):
    """Parse port string into sorted list of ports"""
    ports = set()
    
    # Handle comma-separated and range formats
    for part in port_str.split(','):
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    
    return sorted(ports)

def get_mac_vendor(mac):
    """Look up vendor from MAC address OUI"""
    oui = mac[:8].replace(':', '').upper()
    vendors = {
        "001C42": "Apple",
        "000C29": "VMware",
        "001D0F": "Cisco",
        "001B21": "Huawei",
        "001E68": "Dell",
        "002590": "TP-Link",
        "3C5AB4": "Google",
        "B827EB": "Raspberry Pi"
    }
    return vendors.get(oui, "Unknown")

def is_root():
    """Check if running with root privileges"""
    return os.geteuid() == 0

def get_os_info():
    """Get current operating system information"""
    return {
        "platform": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python_version": platform.python_version()
    }

def random_ip():
    """Generate a random IP address"""
    return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

def timestamp():
    """Get current timestamp in ISO format"""
    return datetime.now().isoformat()

def validate_ip(ip):
    """Validate IPv4 address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_network_interfaces():
    """Get available network interfaces"""
    if platform.system() == "Linux":
        try:
            output = subprocess.check_output(["ip", "-o", "link", "show"]).decode()
            interfaces = re.findall(r"\d+: (\w+):", output)
            return interfaces
        except:
            return []
    elif platform.system() == "Windows":
        return ["Ethernet", "Wi-Fi"]
    else:
        return ["en0", "en1", "wlan0", "wlan1"]

def print_banner():
    """Print tool banner with color"""
    banner = f"""
{Color.RED}
 ██▀███  ▓█████ ▓█████▄ ▓█████  ██▀███   ███▄ ▄███▓
▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌▓█   ▀ ▓██ ▒ ██▒▓██▒▀█▀ ██▒
▓██ ░▄█ ▒▒███   ░██   █▌▒███   ▓██ ░▄█ ▒▓██    ▓██░
▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌▒▓█  ▄ ▒██▀▀█▄  ▒██    ▒██ 
░██▓ ▒██▒░▒████▒░▒████▓ ░▒████▒░██▓ ▒██▒▒██▒   ░██▒
░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ░  ░
  ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒  ░ ░  ░  ░▒ ░ ▒░░  ░      ░
   ░░   ░    ░    ░ ░  ░    ░     ░░   ░ ░      ░   
    ░        ░  ░   ░       ░  ░   ░            ░   
               ░                                     
{Color.END}
{Color.BLUE}RebelNmap v2.0 - Advanced Network Reconnaissance Platform{Color.END}
{Color.YELLOW}Use only on networks you own or have permission to scan!{Color.END}
"""
    print(banner)

def save_results(data, filename, format='json'):
    """Save results to file in specified format"""
    try:
        if format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        elif format.lower() == 'csv':
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header based on data structure
                if isinstance(data, dict) and 'results' in data:
                    writer.writerow(data['results'][0].keys())
                    for item in data['results']:
                        writer.writerow(item.values())
                else:
                    writer.writerow(['Host', 'Port', 'Status', 'Service'])
                    for host, ports in data.items():
                        for port, info in ports.items():
                            writer.writerow([host, port, info['status'], info['service']])
            return True
        else:
            return False
    except Exception as e:
        print(Color.red(f"Error saving results: {str(e)}"))
        return False

def is_port_open(ip, port, timeout=1):
    """Quick port check without banner grabbing"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except:
        return False

def get_public_ip():
    """Get public IP address using external service"""
    try:
        import requests
        return requests.get('https://api.ipify.org').text
    except:
        return "Unknown"

def generate_phishing_payload(port):
    """Generate protocol-specific phishing payloads"""
    payloads = {
        21: b"USER anonymous\r\nPASS guest\r\n",
        22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n",
        25: b"EHLO example.com\r\nMAIL FROM: <trusted@domain.com>\r\n",
        80: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        443: b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
        3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00"
    }
    return payloads.get(port, b"PROBE " + os.urandom(4) + b"\r\n")

def get_tcp_services():
    """Return common TCP services and ports"""
    return {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle DB",
        2049: "NFS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt"
    }

def get_udp_services():
    """Return common UDP services and ports"""
    return {
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP",
        123: "NTP",
        137: "NetBIOS",
        138: "NetBIOS",
        139: "NetBIOS",
        161: "SNMP",
        162: "SNMP Trap",
        500: "IPSec",
        514: "Syslog",
        520: "RIP",
        1900: "UPnP",
        4500: "IPsec NAT-T",
        5353: "mDNS"
    }

if __name__ == "__main__":
    # Test utility functions
    print(Color.bold("\n=== RebelNmap Utilities Test ==="))
    print(f"Timestamp: {timestamp()}")
    print(f"Resolved 'google.com': {dns_lookup('google.com')}")
    print(f"Reverse DNS for '8.8.8.8': {reverse_dns('8.8.8.8')}")
    print(f"CIDR to IPs (192.168.1.0/29): {cidr_to_ips('192.168.1.0/29')}")
    print(f"Parsed ports '80,443,1000-1005': {parse_ports('80,443,1000-1005')}")
    print(f"Running as root: {is_root()}")
    print(f"Current OS info: {json.dumps(get_os_info(), indent=2)}")
    print(f"Generated random IP: {random_ip()}")
    print(f"Validate IP '192.168.1.256': {validate_ip('192.168.1.256')}")
    print(f"Network interfaces: {get_network_interfaces()}")
    print(f"Public IP: {get_public_ip()}")
    print(f"TCP services: {list(get_tcp_services().items())[:5]}...")
    print(f"UDP services: {list(get_udp_services().items())[:5]}...")
    print(f"Phishing payload for port 80: {generate_phishing_payload(80)}")