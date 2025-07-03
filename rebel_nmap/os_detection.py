#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# os_detection.py - Advanced OS Fingerprinting Engine

import socket
import struct
import subprocess
import re
import platform
import random
import json
from scapy.all import IP, TCP, ICMP, sr1, conf
from .utils import Color

class OSDetector:
    """Advanced OS fingerprinting using multiple techniques"""
    
    def __init__(self, target):
        self.target = target
        self.results = {}
        self.signatures = {
            'ttl': {
                32: "Windows 95/98",
                64: "Linux/Unix",
                128: "Windows NT/XP/7/10",
                255: "Solaris/Cisco"
            },
            'tcp_window': {
                16384: "Linux (older)",
                5840: "Linux (kernel 2.4+)",
                8192: "Windows XP",
                64240: "Windows 7/8/10",
                65535: "FreeBSD"
            },
            'tcp_flags': {
                "0x04": "Windows (RST)",
                "0x12": "Linux/Unix (SYN-ACK)"
            },
            'icmp': {
                "type=3/code=3": "Windows",
                "type=11/code=0": "Linux"
            }
        }
    
    def ttl_analysis(self):
        """Determine OS based on TTL values"""
        try:
            if platform.system().lower() == "windows":
                cmd = ['ping', '-n', '1', self.target]
            else:
                cmd = ['ping', '-c', '1', self.target]
            
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
            
            if match:
                ttl = int(match.group(1))
                # Normalize TTL to common base values
                if ttl <= 32: normalized = 32
                elif 33 <= ttl <= 64: normalized = 64
                elif 65 <= ttl <= 128: normalized = 128
                else: normalized = 255
                
                os_guess = self.signatures['ttl'].get(normalized, f"Unknown (TTL: {ttl})")
                self.results['ttl'] = {"value": ttl, "normalized": normalized, "os": os_guess}
                return os_guess
            return "TTL not found"
        except Exception:
            return "Ping failed"
    
    def tcp_fingerprint(self, port=80):
        """TCP stack fingerprinting using raw sockets"""
        if not hasattr(socket, 'SOCK_RAW'):
            return "Raw sockets not supported"
        
        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Craft SYN packet
            source_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.1.1"
            source_port = random.randint(1025, 65534)
            
            ip_header = struct.pack('!BBHHHBBH4s4s', 
                69, 0, 40, random.randint(1000, 65000), 
                0, 64, 6, 0, 
                socket.inet_aton(source_ip), 
                socket.inet_aton(self.target))
            
            tcp_header = struct.pack('!HHLLBBHHH', 
                port, source_port, random.randint(10000, 4294967295), 0, 
                5 << 4, 0x02, 8192, 0, 0)
            
            s.sendto(ip_header + tcp_header, (self.target, 0))
            s.settimeout(2.0)
            
            # Capture response
            packet = s.recv(1024)
            if packet:
                # Extract IP header (first 20 bytes)
                ip_header = packet[:20]
                ttl = ip_header[8]
                
                # Extract TCP header (starts at byte 20)
                tcp_header = packet[20:40]
                window_size = struct.unpack('!H', tcp_header[14:16])[0]
                flags = tcp_header[13]
                
                # Analyze results
                ttl_os = self.signatures['ttl'].get(ttl, f"Unknown (TTL: {ttl})")
                window_os = self.signatures['tcp_window'].get(window_size, f"Unknown (Window: {window_size})")
                flag_os = self.signatures['tcp_flags'].get(hex(flags), "Unknown flags")
                
                self.results['tcp'] = {
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "ttl": ttl,
                    "window_size": window_size,
                    "flags": hex(flags),
                    "os_ttl": ttl_os,
                    "os_window": window_os,
                    "os_flags": flag_os
                }
                return f"{ttl_os} | {window_os} | {flag_os}"
            return "No TCP response"
        except Exception as e:
            return f"TCP fingerprint failed: {str(e)}"
    
    def scapy_fingerprint(self):
        """Advanced fingerprinting using Scapy"""
        if not self._scapy_available():
            return "Scapy not installed"
        
        try:
            conf.verb = 0  # Disable Scapy output
            
            # ICMP fingerprint
            icmp_resp = sr1(IP(dst=self.target)/ICMP(), timeout=2)
            icmp_signature = ""
            icmp_os = ""
            if icmp_resp:
                if icmp_resp.type == 3 and icmp_resp.code == 3:
                    icmp_signature = "type=3/code=3"
                elif icmp_resp.type == 11 and icmp_resp.code == 0:
                    icmp_signature = "type=11/code=0"
                icmp_os = self.signatures['icmp'].get(icmp_signature, "Unknown ICMP response")
            
            # TCP fingerprint
            tcp_resp = sr1(IP(dst=self.target)/TCP(dport=80, flags="S"), timeout=2)
            tcp_os = ""
            ttl = window = flags = None
            if tcp_resp:
                ttl = tcp_resp[IP].ttl
                window = tcp_resp[TCP].window
                flags = tcp_resp[TCP].flags
                tcp_os = f"{self.signatures['ttl'].get(ttl, 'Unknown')} (Window: {window}, Flags: {flags})"
            
            self.results['scapy'] = {
                "icmp_signature": icmp_signature,
                "tcp_ttl": ttl,
                "tcp_window": window,
                "tcp_flags": flags,
                "os_icmp": icmp_os,
                "os_tcp": tcp_os
            }
            
            return f"ICMP: {icmp_os} | TCP: {tcp_os}"
        except Exception as e:
            return f"Scapy fingerprint failed: {str(e)}"
    
    def _scapy_available(self):
        try:
            import scapy
            return True
        except ImportError:
            return False
    
    def detect(self, methods=("ttl", "tcp", "scapy")):
        """Run all available detection methods"""
        results = []
        
        if "ttl" in methods:
            ttl_result = self.ttl_analysis()
            results.append(f"TTL Analysis: {Color.YELLOW}{ttl_result}{Color.END}")
        
        if "tcp" in methods:
            tcp_result = self.tcp_fingerprint()
            results.append(f"TCP Fingerprint: {Color.YELLOW}{tcp_result}{Color.END}")
        
        if "scapy" in methods and self._scapy_available():
            scapy_result = self.scapy_fingerprint()
            results.append(f"Scapy Fingerprint: {Color.YELLOW}{scapy_result}{Color.END}")
        
        return "\n".join(results)
    
    def get_os_guess(self):
        """Make educated guess based on all collected data"""
        # Weighted decision based on confidence levels
        if 'scapy' in self.results:
            return self.results['scapy'].get('os_tcp', "Unknown")
        elif 'tcp' in self.results:
            return self.results['tcp'].get('os_window', "Unknown")
        elif 'ttl' in self.results:
            return self.results['ttl'].get('os', "Unknown")
        return "Insufficient data"
    
    def get_forensic_data(self):
        """Return complete forensic data as JSON"""
        return json.dumps(self.results, indent=2)

# ======== Example Usage ========
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    
    detector = OSDetector(target)
    print(f"\n{Color.CYAN}=== OS DETECTION FOR {target} ==={Color.END}")
    print(detector.detect())
    
    final_guess = detector.get_os_guess()
    print(f"\n{Color.GREEN}Final OS Guess: {final_guess}{Color.END}")
    
    # Print full forensic data
    print(f"\n{Color.MAGENTA}=== RAW FORENSIC DATA ==={Color.END}")
    print(detector.get_forensic_data())