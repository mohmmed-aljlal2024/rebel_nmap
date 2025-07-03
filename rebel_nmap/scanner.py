#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# scanner.py - Advanced Port Scanning Engine

import json
import socket
import struct
import select
import random
import os
import threading
import time
import re
from datetime import datetime
from .utils import Color

class PortScanner:
    """Advanced port scanning with multiple techniques and evasion"""
    
    def __init__(self, target, timeout=1.5, stealth=False, randomize=False):
        self.target = target
        self.timeout = timeout
        self.stealth = stealth
        self.randomize = randomize
        self.open_ports = {}
        self.scan_stats = {
            'start_time': datetime.now(),
            'ports_scanned': 0,
            'open_ports': 0,
            'filtered_ports': 0,
            'closed_ports': 0
        }
        self.forensic_data = {}
        self.phish_payloads = {
            21: b"USER anonymous\r\nPASS mozilla@example.com\r\n",
            22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n",
            23: b"Telnet Service Ready\r\n",
            25: b"EHLO example.com\r\n",
            80: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
            443: b"CONNECT example.com:443 HTTP/1.0\r\n\r\n",
            3306: b"\x1a\x00\x00\x00\x0a8.0.28",
            3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00"
        }
    
    def has_root(self):
        """Check for root privileges"""
        return os.geteuid() == 0
    
    def generate_probe(self, port):
        """Generate protocol-specific probes"""
        if port in self.phish_payloads:
            return self.phish_payloads[port]
        return b"PROBE " + os.urandom(4) + b"\r\n"
    
    def tcp_connect_scan(self, port):
        """Standard TCP connect scan with banner grabbing"""
        try:
            start_time = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                
                # Send protocol-specific probe
                probe = self.generate_probe(port)
                s.send(probe)
                
                # Receive banner
                banner = s.recv(1024).decode('utf-8', 'ignore')
                elapsed = time.time() - start_time
                
                # Save forensic data
                self.forensic_data[port] = {
                    'method': 'TCP Connect',
                    'status': 'open',
                    'banner': banner,
                    'response_time': f"{elapsed:.4f}s"
                }
                return True, banner
        except (socket.timeout, ConnectionRefusedError):
            self.forensic_data[port] = {'method': 'TCP Connect', 'status': 'closed'}
            return False, ""
        except Exception as e:
            self.forensic_data[port] = {'method': 'TCP Connect', 'status': f'error: {str(e)}'}
            return False, str(e)
    
    def syn_scan(self, port):
        """Stealth SYN scan (requires root)"""
        if not self.has_root():
            return False, "Root required for SYN scan"
        
        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Generate random source IP and port
            src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            src_port = random.randint(1024, 65535)
            seq_num = random.randint(10000, 4294967295)
            
            # Build IP header
            ip_header = struct.pack('!BBHHHBBH4s4s', 
                69, 0, 40, random.randint(1000, 65000), 
                0, 64, 6, 0, 
                socket.inet_aton(src_ip), 
                socket.inet_aton(self.target))
            
            # Build TCP header
            tcp_header = struct.pack('!HHLLBBHHH', 
                port, src_port, seq_num, 0, 
                5 << 4, 0x02, 8192, 0, 0)
            
            # Send SYN packet
            s.sendto(ip_header + tcp_header, (self.target, 0))
            
            # Listen for response
            ready = select.select([s], [], [], self.timeout)
            if ready[0]:
                packet = s.recv(1024)
                if packet:
                    # Check for SYN-ACK (0x12)
                    if packet[33] == 0x12:
                        # Send RST to close connection
                        rst_header = struct.pack('!HHLLBBHHH', 
                            port, src_port, seq_num + 1, 0, 
                            5 << 4, 0x04, 8192, 0, 0)
                        s.sendto(ip_header + rst_header, (self.target, 0))
                        
                        # Save forensic data
                        self.forensic_data[port] = {
                            'method': 'SYN Scan',
                            'status': 'open',
                            'src_ip': src_ip,
                            'src_port': src_port
                        }
                        return True, ""
            return False, ""
        except Exception as e:
            self.forensic_data[port] = {'method': 'SYN Scan', 'status': f'error: {str(e)}'}
            return False, str(e)
        finally:
            s.close()
    
    def udp_scan(self, port):
        """UDP port scanning with service detection"""
        try:
            start_time = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(self.generate_probe(port), (self.target, port))
                data, addr = s.recvfrom(1024)
                elapsed = time.time() - start_time
                
                # Save forensic data
                self.forensic_data[port] = {
                    'method': 'UDP Scan',
                    'status': 'open',
                    'response': data.hex(),
                    'response_time': f"{elapsed:.4f}s"
                }
                return True, data.hex()
        except socket.timeout:
            # Check for ICMP port unreachable
            if self._check_icmp_unreachable(port):
                self.forensic_data[port] = {'method': 'UDP Scan', 'status': 'closed'}
                return False, ""
            self.forensic_data[port] = {'method': 'UDP Scan', 'status': 'open|filtered'}
            return True, "No response"
        except Exception as e:
            self.forensic_data[port] = {'method': 'UDP Scan', 'status': f'error: {str(e)}'}
            return False, str(e)
    
    def _check_icmp_unreachable(self, port):
        """Check for ICMP port unreachable messages"""
        if not self.has_root():
            return False
        
        try:
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_sock.settimeout(0.1)
            icmp_sock.recv(1024)
            return True
        except:
            return False
    
    def service_detection(self, port):
        """Advanced service detection with version probing"""
        try:
            # Try to connect and get detailed banner
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                
                # Send protocol-specific probe
                probe = self.generate_probe(port)
                s.send(probe)
                
                # Receive and decode banner
                banner = s.recv(1024).decode('utf-8', 'ignore')
                
                # Enhanced service matching
                service = self._identify_service(port, banner)
                return service
        except:
            return "Unknown"
    
    def _identify_service(self, port, banner):
        """Identify service based on port and banner"""
        common_services = {
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
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP Proxy"
        }
        
        # First try port-based identification
        if port in common_services:
            service = common_services[port]
        else:
            service = "Unknown"
        
        # Enhance with banner analysis
        if "SSH" in banner:
            service = "SSH"
            match = re.search(r"OpenSSH_(\d+\.\d+[^\s]*)", banner)
            if match:
                service += f" (OpenSSH {match.group(1)})"
        elif "HTTP" in banner or "Server:" in banner:
            service = "HTTP"
            match = re.search(r"Server: ([^\r\n]*)", banner)
            if match:
                service += f" ({match.group(1)})"
        elif "220" in banner and "SMTP" in banner:
            service = "SMTP"
            match = re.search(r"220 ([^\r\n]*)", banner)
            if match:
                service += f" ({match.group(1)})"
        elif "FTP" in banner:
            service = "FTP"
        elif "MySQL" in banner:
            service = "MySQL"
            match = re.search(r"(\d+\.\d+\.\d+[^\s]*)", banner)
            if match:
                service += f" ({match.group(1)})"
        
        return service
    
    def scan_ports(self, ports, scan_type='tcp', threads=100):
        """Scan multiple ports with threading"""
        self.scan_stats['ports'] = list(ports)
        if self.randomize:
            random.shuffle(self.scan_stats['ports'])
        
        port_queue = list(self.scan_stats['ports'])
        self.scan_stats['total_ports'] = len(port_queue)
        lock = threading.Lock()
        
        def worker():
            while port_queue:
                with lock:
                    if not port_queue:
                        return
                    port = port_queue.pop()
                    self.scan_stats['ports_scanned'] += 1
                
                try:
                    if scan_type == 'syn' and self.has_root():
                        status, banner = self.syn_scan(port)
                    elif scan_type == 'udp':
                        status, banner = self.udp_scan(port)
                    else:
                        status, banner = self.tcp_connect_scan(port)
                    
                    with lock:
                        if status:
                            self.scan_stats['open_ports'] += 1
                            service = self.service_detection(port) if scan_type != 'syn' else "Service not detected"
                            self.open_ports[port] = {
                                'status': 'open',
                                'service': service,
                                'banner': banner
                            }
                        else:
                            self.scan_stats['closed_ports'] += 1
                except Exception as e:
                    with lock:
                        self.scan_stats['filtered_ports'] += 1
                        self.open_ports[port] = {
                            'status': 'error',
                            'error': str(e)
                        }
        
        # Create and manage threads
        thread_pool = []
        for _ in range(min(threads, len(ports))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            thread_pool.append(t)
        
        # Wait for completion
        for t in thread_pool:
            t.join()
        
        # Finalize stats
        self.scan_stats['end_time'] = datetime.now()
        self.scan_stats['duration'] = str(self.scan_stats['end_time'] - self.scan_stats['start_time'])
        return self.open_ports
    
    def get_scan_stats(self):
        """Return scan statistics"""
        return self.scan_stats
    
    def get_forensic_data(self):
        """Return complete forensic data"""
        return {
            'target': self.target,
            'scan_config': {
                'timeout': self.timeout,
                'stealth': self.stealth,
                'randomize': self.randomize
            },
            'port_data': self.forensic_data,
            'open_ports': self.open_ports,
            'stats': self.scan_stats
        }
    
    def generate_report(self):
        """Generate human-readable scan report"""
        report = []
        report.append(f"\n{Color.CYAN}=== PORT SCAN REPORT FOR {self.target} ===")
        report.append(f"Scan started: {self.scan_stats['start_time']}")
        report.append(f"Duration: {self.scan_stats['duration']}")
        report.append(f"Ports scanned: {self.scan_stats['ports_scanned']}")
        report.append(f"Open ports: {self.scan_stats['open_ports']}")
        report.append(f"Closed ports: {self.scan_stats['closed_ports']}")
        report.append(f"Filtered ports: {self.scan_stats['filtered_ports']}{Color.END}")
        
        if self.open_ports:
            report.append(f"\n{Color.GREEN}OPEN PORTS:{Color.END}")
            report.append(f"{Color.YELLOW}PORT\tSERVICE\tBANNER{Color.END}")
            for port, data in self.open_ports.items():
                banner = data['banner'][:50] + '...' if len(data['banner']) > 50 else data['banner']
                report.append(f"{port}/tcp\t{data['service']}\t{banner}")
        
        return "\n".join(report)

# ======== Example Usage ========
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ports = [21, 22, 80, 443, 8080, 3306, 3389]
    
    print(f"{Color.CYAN}\n[+] Starting advanced port scan on {target}{Color.END}")
    scanner = PortScanner(target, stealth=True, randomize=True)
    results = scanner.scan_ports(ports, scan_type='tcp', threads=50)
    
    print(scanner.generate_report())
    
    # Print forensic data
    print(f"\n{Color.MAGENTA}=== RAW FORENSIC DATA ==={Color.END}")
    print(json.dumps(scanner.get_forensic_data(), indent=2))