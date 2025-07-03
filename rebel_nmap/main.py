#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# main.py - RebelNmap Core Engine

import argparse
import threading
import time
import json
import csv
import os
import random
from datetime import datetime
from .utils import Color, print_banner, dns_lookup, cidr_to_ips, parse_ports
from .host_discovery import HostDiscovery
from .scanner import PortScanner
from .os_detection import OSDetector
from .exporter import export_json, export_csv
from .cli import RebelCLI

class RebelScanner:
    """Advanced network reconnaissance engine with evasion capabilities"""
    
    def __init__(self, args):
        self.args = args
        self.results = {}
        self.active_hosts = []
        self.ports = []
        self.scan_stats = {
            'start_time': datetime.now(),
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'open_ports_found': 0,
            'services_identified': 0,
            'os_detections': 0
        }
        
    def resolve_targets(self):
        """Convert target specification to IP addresses"""
        print(f"{Color.CYAN}[+] Resolving targets...{Color.END}")
        
        # Handle CIDR ranges
        if '/' in self.args.target:
            targets = cidr_to_ips(self.args.target)
            print(f"  Expanded to {len(targets)} IP addresses")
            return targets
        
        # Handle single IP/hostname
        ip = dns_lookup(self.args.target)
        if ip:
            print(f"  Resolved {self.args.target} -> {ip}")
            return [ip]
        
        print(f"{Color.RED}Error: Invalid target specification{Color.END}")
        return []

    def discover_hosts(self):
        """Perform host discovery using configured methods"""
        print(f"{Color.MAGENTA}[+] Starting host discovery...{Color.END}")
        
        # Create discovery engine
        discovery = HostDiscovery(self.args.target)
        
        # Select discovery method based on arguments
        if self.args.tcp_syn_ping:
            ports = parse_ports(self.args.tcp_syn_ping)
            print(f"  TCP SYN discovery on ports: {', '.join(map(str, ports))}")
            self.active_hosts = discovery.tcp_syn_discovery(ports)
        elif self.args.tcp_ack_ping:
            ports = parse_ports(self.args.tcp_ack_ping)
            print(f"  TCP ACK discovery on ports: {', '.join(map(str, ports))}")
            self.active_hosts = discovery.tcp_syn_discovery(ports)  # ACK uses same method
        elif self.args.udp_ping:
            ports = parse_ports(self.args.udp_ping)
            print(f"  UDP discovery on ports: {', '.join(map(str, ports))}")
            self.active_hosts = discovery.udp_discovery(ports)
        elif not self.args.no_ping:
            print("  ICMP ping sweep")
            self.active_hosts = discovery.ping_sweep()
        else:
            print(f"{Color.YELLOW}  Skipping host discovery (--no-ping){Color.END}")
            self.active_hosts = self.resolve_targets()
        
        # Fallback if no hosts found
        if not self.active_hosts:
            print(f"{Color.YELLOW}  No active hosts found, trying ARP scan{Color.END}")
            self.active_hosts = discovery.arp_scan()
        
        if self.active_hosts:
            print(f"{Color.GREEN}  Found {len(self.active_hosts)} active hosts{Color.END}")
            if self.args.verbose:
                for host in self.active_hosts:
                    print(f"    - {host}")
        else:
            print(f"{Color.RED}  No active hosts found{Color.END}")
        
        return bool(self.active_hosts)

    def scan_single_host(self, host):
        """Perform comprehensive scan on a single host"""
        host_results = {
            'ports': {},
            'os': {},
            'services': {}
        }
        
        # OS detection
        if self.args.os_detection:
            print(f"{Color.CYAN}\n[+] OS detection for {host}{Color.END}")
            detector = OSDetector(host)
            os_result = detector.detect()
            host_results['os'] = detector.results
            host_results['os_guess'] = detector.get_os_guess()
            print(f"  OS Guess: {Color.YELLOW}{host_results['os_guess']}{Color.END}")
            self.scan_stats['os_detections'] += 1
        
        # Port scanning
        scanner = PortScanner(
            host, 
            timeout=self.calculate_timeout(),
            stealth=getattr(self.args, 'syn_stealth', False),
            randomize=getattr(self.args, 'randomize', False)
        )
        
        print(f"{Color.BLUE}[+] Scanning {len(self.ports)} ports on {host}{Color.END}")
        open_ports = scanner.scan_ports(
            self.ports, 
            scan_type='syn' if self.args.syn_stealth else 'tcp',
            threads=self.args.max_parallelism
        )
        
        # Service detection
        if self.args.service_detection:
            print(f"{Color.MAGENTA}[+] Service detection on open ports{Color.END}")
            for port, data in open_ports.items():
                if data['status'] == 'open':
                    service = scanner.service_detection(port)
                    data['service'] = service
                    host_results['services'][port] = service
                    self.scan_stats['services_identified'] += 1
                    print(f"  Port {port}: {service}")
        
        host_results['ports'] = open_ports
        self.scan_stats['ports_scanned'] += len(self.ports)
        self.scan_stats['open_ports_found'] += len(open_ports)
        self.scan_stats['hosts_scanned'] += 1
        
        return host_results

    def calculate_timeout(self):
        """Calculate timeout based on timing profile"""
        timeouts = {
            0: 5000,  # Paranoid
            1: 2000,  # Sneaky
            2: 1000,  # Polite
            3: 500,   # Normal
            4: 200,   # Aggressive
            5: 100    # Insane
        }
        return timeouts.get(self.args.timing, 500) / 1000.0

    def run(self):
        """Execute the full reconnaissance workflow"""
        print_banner()
        print(self.args.summary if hasattr(self.args, 'summary') else "")
        
        # Parse ports
        if self.args.top_ports:
            from .utils import get_tcp_services
            top_ports = sorted(get_tcp_services().keys())
            self.ports = top_ports[:self.args.top_ports]
            print(f"{Color.CYAN}Scanning top {self.args.top_ports} TCP ports{Color.END}")
        else:
            self.ports = parse_ports(self.args.ports)
            print(f"{Color.CYAN}Scanning {len(self.ports)} specified ports{Color.END}")
        
        # Host discovery
        if not self.discover_hosts():
            return
        
        # Scan all active hosts
        for host in self.active_hosts:
            self.results[host] = self.scan_single_host(host)
        
        # Finalize stats
        self.scan_stats['end_time'] = datetime.now()
        self.scan_stats['duration'] = str(self.scan_stats['end_time'] - self.scan_stats['start_time'])
        
        # Output results
        self.generate_reports()
        
        # Print summary
        self.print_summary()

    def generate_reports(self):
        """Generate all requested output reports"""
        # Normal output to console
        if self.args.normal_output:
            self.save_normal_output(self.args.normal_output)
            print(f"{Color.GREEN}Normal output saved to {self.args.normal_output}{Color.END}")
        else:
            self.print_normal_output()
        
        # JSON output
        if self.args.json_output:
            export_json(self.results, self.args.json_output)
            print(f"{Color.GREEN}JSON output saved to {self.args.json_output}{Color.END}")
        
        # XML output
        if self.args.xml_output:
            self.save_xml_output(self.args.xml_output)
            print(f"{Color.GREEN}XML output saved to {self.args.xml_output}{Color.END}")
        
        # Grepable output
        if self.args.grep_output:
            self.save_grep_output(self.args.grep_output)
            print(f"{Color.GREEN}Grepable output saved to {self.args.grep_output}{Color.END}")

    def print_normal_output(self):
        """Print results to console in normal format"""
        print(f"\n{Color.CYAN}=== SCAN RESULTS ==={Color.END}")
        for host, data in self.results.items():
            print(f"\n{Color.BOLD}Host: {host}{Color.END}")
            
            # OS information
            if data.get('os_guess'):
                print(f"OS: {Color.YELLOW}{data['os_guess']}{Color.END}")
            
            # Port information
            if data['ports']:
                print(f"{Color.GREEN}PORT\tSTATE\tSERVICE{Color.END}")
                for port, info in data['ports'].items():
                    if info['status'] == 'open':
                        service = info.get('service', 'unknown')
                        print(f"{port}/tcp\topen\t{service}")
            else:
                print(f"{Color.RED}No open ports found{Color.END}")

    def save_normal_output(self, filename):
        """Save normal output to file"""
        with open(filename, 'w') as f:
            f.write(f"# RebelNmap Scan Report\n")
            f.write(f"# Scan Date: {datetime.now().isoformat()}\n")
            f.write(f"# Target: {self.args.target}\n")
            f.write(f"# Scan Type: {'SYN Stealth' if self.args.syn_stealth else 'TCP Connect'}\n\n")
            
            for host, data in self.results.items():
                f.write(f"\nHost: {host}\n")
                
                if data.get('os_guess'):
                    f.write(f"OS: {data['os_guess']}\n")
                
                if data['ports']:
                    f.write("PORT\tSTATE\tSERVICE\n")
                    for port, info in data['ports'].items():
                        if info['status'] == 'open':
                            service = info.get('service', 'unknown')
                            f.write(f"{port}/tcp\topen\t{service}\n")
                else:
                    f.write("No open ports found\n")

    def save_xml_output(self, filename):
        """Generate XML output format"""
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom
        
        # Create root element
        nmaprun = Element('nmaprun', {
            'scanner': 'RebelNmap',
            'start': str(self.scan_stats['start_time'].timestamp()),
            'version': '2.0'
        })
        
        # Add scan information
        scaninfo = SubElement(nmaprun, 'scaninfo', {
            'type': 'syn' if self.args.syn_stealth else 'connect',
            'protocol': 'tcp',
            'numservices': str(len(self.ports))
        })
        
        # Add hosts
        for host, data in self.results.items():
            host_elem = SubElement(nmaprun, 'host')
            address = SubElement(host_elem, 'address', {'addr': host, 'addrtype': 'ipv4'})
            
            # OS information
            if data.get('os_guess'):
                os_elem = SubElement(host_elem, 'os')
                osmatch = SubElement(os_elem, 'osmatch', {
                    'name': data['os_guess'],
                    'accuracy': '90'
                })
            
            # Port information
            ports_elem = SubElement(host_elem, 'ports')
            for port, info in data['ports'].items():
                if info['status'] == 'open':
                    port_elem = SubElement(ports_elem, 'port', {
                        'protocol': 'tcp',
                        'portid': str(port)
                    })
                    state = SubElement(port_elem, 'state', {'state': 'open'})
                    service = SubElement(port_elem, 'service', {
                        'name': info.get('service', 'unknown'),
                        'method': 'probed'
                    })
        
        # Format and write XML
        rough_xml = tostring(nmaprun, 'utf-8')
        parsed = minidom.parseString(rough_xml)
        with open(filename, 'w') as f:
            f.write(parsed.toprettyxml(indent="  "))

    def save_grep_output(self, filename):
        """Generate grepable output format"""
        with open(filename, 'w') as f:
            for host, data in self.results.items():
                # Host status
                f.write(f"Host: {host} () Status: Up\n")
                
                # Port information
                for port, info in data['ports'].items():
                    if info['status'] == 'open':
                        service = info.get('service', 'unknown').split()[0]
                        f.write(f"{port}/tcp open  {service}\n")

    def print_summary(self):
        """Print scan summary"""
        duration = self.scan_stats['end_time'] - self.scan_stats['start_time']
        print(f"\n{Color.CYAN}=== SCAN SUMMARY ===")
        print(f"Scan completed in {duration}")
        print(f"Hosts scanned: {self.scan_stats['hosts_scanned']}")
        print(f"Ports scanned: {self.scan_stats['ports_scanned']}")
        print(f"Open ports found: {self.scan_stats['open_ports_found']}")
        print(f"Services identified: {self.scan_stats['services_identified']}")
        print(f"OS detections: {self.scan_stats['os_detections']}")
        print("===================={Color.END}")
        
        # Print vulnerability highlights
        self.print_vulnerability_summary()

    def print_vulnerability_summary(self):
        """Highlight potential attack surfaces"""
        vuln_hosts = []
        
        for host, data in self.results.items():
            for port, info in data['ports'].items():
                if info['status'] == 'open':
                    service = info.get('service', '').lower()
                    
                    # Common vulnerable services
                    if 'http' in service:
                        vuln_hosts.append(f"{host}:{port} (HTTP service)")
                    elif 'ftp' in service and 'anonymous' not in service:
                        vuln_hosts.append(f"{host}:{port} (FTP without anonymous)")
                    elif 'smb' in service or 'netbios' in service:
                        vuln_hosts.append(f"{host}:{port} (SMB/NetBIOS service)")
                    elif 'rdp' in service:
                        vuln_hosts.append(f"{host}:{port} (RDP service)")
                    elif 'ssh' in service and '7.' not in service:
                        vuln_hosts.append(f"{host}:{port} (Older SSH service)")
                    elif 'mysql' in service or 'mssql' in service:
                        vuln_hosts.append(f"{host}:{port} (Database service)")
        
        if vuln_hosts:
            print(f"\n{Color.RED}[!] POTENTIAL ATTACK SURFACES:{Color.END}")
            for vuln in vuln_hosts:
                print(f"  - {vuln}")
            print(f"{Color.YELLOW}Consider further investigation of these services{Color.END}")

def main():
    """Main entry point for RebelNmap"""
    try:
        # Parse command-line arguments
        cli = RebelCLI()
        args = cli.parse_args()
        
        if not cli.validate_args():
            exit(1)
        
        # Create configuration summary
        args.summary = cli.get_config_summary()
        
        # Initialize and run scanner
        scanner = RebelScanner(args)
        scanner.run()
        
    except KeyboardInterrupt:
        print(f"\n{Color.RED}Scan aborted by user!{Color.END}")
        exit(1)
    except Exception as e:
        print(f"{Color.RED}Fatal error: {str(e)}{Color.END}")
        exit(1)

if __name__ == "__main__":
    main()