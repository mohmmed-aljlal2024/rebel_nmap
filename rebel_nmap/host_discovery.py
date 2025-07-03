#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# host_discovery.py - Advanced Host Discovery Engine

import json
import os
import re
import platform
import subprocess
import socket
import struct
import ipaddress
import threading
import time
import random
from .utils import Color
try:
    from scapy.all import ARP, Ether, srp, conf, ICMP, IP
except ImportError:
    pass
class HostDiscovery:
    """Advanced host discovery using multiple techniques"""
    
    def __init__(self, target):
        self.target = target
        self.active_hosts = []
        self.techniques_used = []
        self.forensic_data = {}
        self.arp_cache = {}
        
    def has_root(self):
        """Check for root privileges"""
        return os.geteuid() == 0
    
    def dns_lookup(self):
        """Resolve hostnames to IP addresses"""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return None
    
    def cidr_to_ips(self):
        """Convert CIDR notation to individual IPs"""
        return [str(ip) for ip in ipaddress.IPv4Network(self.target)]
    
    def ping_sweep(self, timeout=1, count=1):
        """ICMP-based host discovery"""
        active = []
        targets = self.cidr_to_ips() if '/' in self.target else [self.target]
        
        def ping_host(host):
            try:
                if platform.system().lower() == "windows":
                    cmd = ['ping', '-n', str(count), '-w', str(timeout*1000), host]
                else:
                    cmd = ['ping', '-c', str(count), '-W', str(timeout), host]
                
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
                if "ttl=" in output.lower():
                    with threading.Lock():
                        active.append(host)
                        self.forensic_data[host] = {"method": "ICMP", "response": output}
            except:
                pass
        
        threads = []
        for host in targets:
            t = threading.Thread(target=ping_host, args=(host,))
            t.daemon = True
            t.start()
            threads.append(t)
            time.sleep(0.01)  # Prevent flooding
            
        for t in threads:
            t.join(timeout=timeout+1)
        
        self.techniques_used.append("ICMP Ping Sweep")
        return active
    
    def arp_scan(self, interface='eth0'):
        """ARP-based host discovery for local networks"""
        if not self.has_root():
            return []
        
        try:
            # Get network range from target
            if '/' not in self.target:
                network = '.'.join(self.target.split('.')[:3]) + '.0/24'
            else:
                network = self.target
                
            # Create ARP request
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send and capture responses
            result = srp(packet, timeout=3, iface=interface, verbose=0)[0]
            
            active = []
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                active.append(ip)
                self.arp_cache[ip] = mac
                self.forensic_data[ip] = {
                    "method": "ARP",
                    "mac": mac,
                    "vendor": self.get_vendor(mac)
                }
            
            self.techniques_used.append("ARP Scan")
            return active
        except Exception as e:
            return []
    
    def tcp_syn_discovery(self, ports=[80, 443, 22]):
        """TCP SYN-based host discovery"""
        if not self.has_root():
            return []
        
        active = []
        targets = self.cidr_to_ips() if '/' in self.target else [self.target]
        
        def syn_probe(host, port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                # Spoof source IP
                src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.1.1"
                
                # IP header
                ip_header = struct.pack('!BBHHHBBH4s4s', 
                    69, 0, 40, random.randint(1000, 65000), 
                    0, 64, 6, 0, 
                    socket.inet_aton(src_ip), 
                    socket.inet_aton(host))
                
                # TCP header
                tcp_header = struct.pack('!HHLLBBHHH', 
                    port, random.randint(1024, 65535), 
                    random.randint(10000, 4294967295), 0, 
                    5 << 4, 0x02, 8192, 0, 0)
                
                s.sendto(ip_header + tcp_header, (host, 0))
                s.settimeout(1)
                
                # Capture response
                packet = s.recv(1024)
                if packet:
                    # Check SYN-ACK response
                    if packet[33] == 0x12:
                        with threading.Lock():
                            if host not in active:
                                active.append(host)
                            self.forensic_data.setdefault(host, {"method": "TCP SYN", "ports": []})
                            self.forensic_data[host]["ports"].append(port)
            except:
                pass
            finally:
                s.close()
        
        # Probe all targets on multiple ports
        threads = []
        for host in targets:
            for port in ports:
                t = threading.Thread(target=syn_probe, args=(host, port))
                t.daemon = True
                t.start()
                threads.append(t)
                time.sleep(0.001)
        
        for t in threads:
            t.join(timeout=2)
        
        self.techniques_used.append("TCP SYN Discovery")
        return active
    
    def udp_discovery(self, ports=[53, 137, 161]):
        """UDP-based host discovery"""
        active = []
        targets = self.cidr_to_ips() if '/' in self.target else [self.target]
        
        def udp_probe(host, port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(0.5)
                    s.sendto(b"PROBE", (host, port))
                    s.recvfrom(1024)
                    with threading.Lock():
                        if host not in active:
                            active.append(host)
                        self.forensic_data.setdefault(host, {"method": "UDP", "ports": []})
                        self.forensic_data[host]["ports"].append(port)
            except socket.timeout:
                # ICMP Port Unreachable indicates host is alive
                if self.check_icmp_unreachable(host):
                    with threading.Lock():
                        if host not in active:
                            active.append(host)
            except:
                pass
        
        threads = []
        for host in targets:
            for port in ports:
                t = threading.Thread(target=udp_probe, args=(host, port))
                t.daemon = True
                t.start()
                threads.append(t)
                time.sleep(0.001)
        
        for t in threads:
            t.join(timeout=1)
        
        self.techniques_used.append("UDP Discovery")
        return active
    
    def check_icmp_unreachable(self, host):
        """Check for ICMP port unreachable responses"""
        if not self.has_root():
            return False
            
        try:
            # Use raw socket to capture ICMP
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(0.5)
            s.recvfrom(1024)
            return True
        except socket.timeout:
            return False
        except:
            return False
    
    def get_vendor(self, mac):
        """Get vendor from MAC address"""
        oui = mac[:8].replace(':', '').upper()
        try:
            from requests import get
            response = get(f"https://api.macvendors.com/{oui}")
            return response.text if response.status_code == 200 else "Unknown"
        except:
            return "Unknown"
    
    def hybrid_discovery(self, aggressive=False):
        """Combine multiple discovery techniques"""
        # Try simple ICMP first
        self.active_hosts = self.ping_sweep()
        
        # If no results, try more advanced techniques
        if not self.active_hosts or aggressive:
            # ARP scan for local networks
            if '/' in self.target and self.target.endswith('/24'):
                self.active_hosts = self.arp_scan()
            
            # TCP/UDP for remote hosts
            if not self.active_hosts:
                self.active_hosts = self.tcp_syn_discovery()
            
            if not self.active_hosts:
                self.active_hosts = self.udp_discovery()
        
        # Final fallback: all addresses in CIDR
        if not self.active_hosts and '/' in self.target:
            self.active_hosts = self.cidr_to_ips()
            self.techniques_used.append("CIDR Fallback")
        
        return self.active_hosts
    
    def get_forensic_data(self):
        """Return complete discovery forensic data"""
        return {
            "target": self.target,
            "active_hosts": self.active_hosts,
            "techniques": self.techniques_used,
            "host_data": self.forensic_data,
            "arp_cache": self.arp_cache
        }

# ======== Example Usage ========
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    
    print(f"{Color.CYAN}\n[+] Starting host discovery on {target}{Color.END}")
    detector = HostDiscovery(target)
    active_hosts = detector.hybrid_discovery(aggressive=True)
    
    if active_hosts:
        print(f"{Color.GREEN}[+] Found {len(active_hosts)} active hosts:{Color.END}")
        for host in active_hosts:
            print(f"  - {host}")
        
        print(f"\n{Color.MAGENTA}[+] Discovery techniques used: {', '.join(detector.techniques_used)}{Color.END}")
        
        print(f"\n{Color.YELLOW}[+] Forensic data:{Color.END}")
        print(json.dumps(detector.get_forensic_data(), indent=2))
    else:
        print(f"{Color.RED}[-] No active hosts found{Color.END}")
