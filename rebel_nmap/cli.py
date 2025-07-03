#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# cli.py - Advanced Command-Line Interface

import argparse
import ipaddress
import textwrap
from .utils import Color, print_banner

class RebelCLI:
    """Advanced command-line interface for RebelNmap"""
    
    def __init__(self):
        self.parser = self.create_parser()
        self.args = None
        
    def create_parser(self):
        """Create the argument parser with advanced options"""
        parser = argparse.ArgumentParser(
            description=f"{Color.RED}RebelNmap v2.0 - Advanced Network Reconnaissance Tool{Color.END}",
            epilog=f"{Color.YELLOW}Warning: Unauthorized scanning is illegal. Use at your own risk.{Color.END}",
            formatter_class=argparse.RawTextHelpFormatter,
            usage=f"{Color.BLUE}rebelmap [TARGET] [OPTIONS]{Color.END}"
        )
        
        # Target specification
        target_group = parser.add_argument_group(f"{Color.CYAN}Target Specification{Color.END}")
        target_group.add_argument(
            "target",
            help="Target IP address, hostname, or CIDR range\n"
                 f"{Color.MAGENTA}Examples: 192.168.1.1, example.com, 10.0.0.0/24{Color.END}"
        )
        
        # Scan techniques
        scan_group = parser.add_argument_group(f"{Color.CYAN}Scan Techniques{Color.END}")
        scan_group.add_argument(
            "-sT", "--tcp-connect",
            action="store_true",
            help="TCP connect scan (default for non-root users)"
        )
        perf_group = parser.add_argument_group(f"{Color.CYAN}Timing and Performance{Color.END}")
        perf_group.add_argument(
            '--randomize',
            action='store_true',
            help="Randomize port scanning order for stealth"
        )
        scan_group.add_argument(
            "-sS", "--syn-stealth",
            action="store_true",
            help="SYN stealth scan (requires root privileges)"
        )
        scan_group.add_argument(
            "-sU", "--udp-scan",
            action="store_true",
            help="UDP port scanning"
        )
        scan_group.add_argument(
            "-sA", "--ack-scan",
            action="store_true",
            help="ACK scan (firewall mapping)"
        )
        scan_group.add_argument(
            "-sF", "--fin-scan",
            action="store_true",
            help="FIN scan (stealthier port detection)"
        )
        
        # Port specification
        port_group = parser.add_argument_group(f"{Color.CYAN}Port Specification{Color.END}")
        port_group.add_argument(
            "-p", "--ports",
            default="1-1024,21-25,80,443,3306,3389,8080",
            help=textwrap.dedent(f"""\
            Port ranges to scan (comma-separated or hyphen ranges)
            {Color.MAGENTA}Examples:
              -p 80,443
              -p 1-1000
              -p 22,80,443,8080-9000{Color.END}""")
        )
        port_group.add_argument(
            "--top-ports",
            type=int,
            metavar="N",
            help=f"Scan top N most common ports {Color.MAGENTA}(Default: 100){Color.END}"
        )
        port_group.add_argument(
            "--port-ratio",
            type=float,
            metavar="R",
            help=f"Scan ports with frequency ratio > R {Color.MAGENTA}(0.0-1.0){Color.END}"
        )
        
        # Service and OS detection
        detection_group = parser.add_argument_group(f"{Color.CYAN}Service and OS Detection{Color.END}")
        detection_group.add_argument(
            "-sV", "--service-detection",
            action="store_true",
            help="Probe open ports to determine service/version info"
        )
        detection_group.add_argument(
            "--version-intensity",
            type=int,
            choices=range(0, 10),
            default=7,
            help="Set version scan intensity (0=light, 9=all probes)"
        )
        detection_group.add_argument(
            "-O", "--os-detection",
            action="store_true",
            help="Enable OS detection using multiple techniques"
        )
        detection_group.add_argument(
            "--osscan-limit",
            action="store_true",
            help="Only detect OS for responsive hosts"
        )
        
        # Host discovery
        host_group = parser.add_argument_group(f"{Color.CYAN}Host Discovery{Color.END}")
        host_group.add_argument(
            "-Pn", "--no-ping",
            action="store_true",
            help="Treat all hosts as online (skip host discovery)"
        )
        host_group.add_argument(
            "-PS", "--tcp-syn-ping",
            metavar="PORTLIST",
            help="TCP SYN discovery on specified ports"
        )
        host_group.add_argument(
            "-PA", "--tcp-ack-ping",
            metavar="PORTLIST",
            help="TCP ACK discovery on specified ports"
        )
        host_group.add_argument(
            "-PU", "--udp-ping",
            metavar="PORTLIST",
            help="UDP discovery on specified ports"
        )
        host_group.add_argument(
            "--traceroute",
            action="store_true",
            help="Trace path to host"
        )
        
        # Timing and performance
        perf_group = parser.add_argument_group(f"{Color.CYAN}Timing and Performance{Color.END}")
        perf_group.add_argument(
            "-T", "--timing",
            type=int,
            choices=range(0, 6),
            default=3,
            help=textwrap.dedent(f"""\
            Set timing template (higher is faster)
            {Color.MAGENTA}0: Paranoid   1: Sneaky    2: Polite
            3: Normal    4: Aggressive  5: Insane{Color.END}""")
        )
        perf_group.add_argument(
            "--max-rtt-timeout",
            type=int,
            default=1000,
            metavar="MS",
            help="Maximum probe round-trip time"
        )
        perf_group.add_argument(
            "--min-rtt-timeout",
            type=int,
            default=100,
            metavar="MS",
            help="Minimum probe round-trip time"
        )
        perf_group.add_argument(
            "--max-parallelism",
            type=int,
            default=100,
            metavar="NUM",
            help="Maximum parallel probes"
        )
        perf_group.add_argument(
            "--min-rate",
            type=int,
            metavar="NUM",
            help="Minimum packet sending rate"
        )
        
        # Output options
        output_group = parser.add_argument_group(f"{Color.CYAN}Output Options{Color.END}")
        output_group.add_argument(
            "-oN", "--normal-output",
            metavar="FILE",
            help="Output in normal format to specified file"
        )
        output_group.add_argument(
            "-oX", "--xml-output",
            metavar="FILE",
            help="Output in XML format to specified file"
        )
        output_group.add_argument(
            "-oJ", "--json-output",
            metavar="FILE",
            help="Output in JSON format to specified file"
        )
        output_group.add_argument(
            "-oG", "--grep-output",
            metavar="FILE",
            help="Output in grepable format to specified file"
        )
        output_group.add_argument(
            "-v", "--verbose",
            action="count",
            default=0,
            help="Increase verbosity level (use -vv for more)"
        )
        output_group.add_argument(
            "-d", "--debug",
            action="count",
            default=0,
            help="Increase debugging level (use -dd for more)"
        )
        
        # Advanced options
        adv_group = parser.add_argument_group(f"{Color.CYAN}Advanced Options{Color.END}")
        adv_group.add_argument(
            "--spoof-mac",
            metavar="MAC",
            help="Spoof source MAC address"
        )
        adv_group.add_argument(
            "--badsum",
            action="store_true",
            help="Use invalid checksums to evade firewalls"
        )
        adv_group.add_argument(
            "--data-length",
            type=int,
            default=0,
            metavar="NUM",
            help="Append random data to packets"
        )
        adv_group.add_argument(
            "--ttl",
            type=int,
            metavar="VALUE",
            help="Set IP time-to-live field"
        )
        adv_group.add_argument(
            "--source-port",
            metavar="PORT",
            help="Use specified source port"
        )
        
        # Evasion options
        evasion_group = parser.add_argument_group(f"{Color.CYAN}Firewall Evasion{Color.END}")
        evasion_group.add_argument(
            "-f", "--fragment",
            action="store_true",
            help="Fragment packets for stealth"
        )
        evasion_group.add_argument(
            "--mtu",
            type=int,
            metavar="SIZE",
            help="Set custom MTU for fragmentation"
        )
        evasion_group.add_argument(
            "-D", "--decoy",
            metavar="HOST1,HOST2,...",
            help="Cloak scan with decoys"
        )
        evasion_group.add_argument(
            "-S", "--spoof-ip",
            metavar="IP",
            help="Spoof source IP address"
        )
        evasion_group.add_argument(
            "-e", "--interface",
            metavar="IFACE",
            help="Use specified network interface"
        )
        evasion_group.add_argument(
            "--proxies",
            metavar="PROXY_URL",
            help="Use HTTP/SOCKS proxies for scan"
        )
        
        return parser
        
    def parse_args(self):
        """Parse command-line arguments with error handling"""
        try:
            self.args = self.parser.parse_args()
            return self.args
        except argparse.ArgumentError as e:
            print(f"{Color.RED}Argument error: {str(e)}{Color.END}")
            self.parser.print_usage()
            exit(1)
        except SystemExit:
            # Print help on invalid arguments
            print_banner()
            self.parser.print_help()
            exit(0)
            
    def validate_args(self):
        """Validate the provided arguments"""
        # Validate target format
        if '/' in self.args.target and not self.is_valid_cidr(self.args.target):
            print(f"{Color.RED}Error: Invalid CIDR format - {self.args.target}{Color.END}")
            return False
            
        # Validate port specification
        if not self.is_valid_ports(self.args.ports):
            print(f"{Color.RED}Error: Invalid port specification - {self.args.ports}{Color.END}")
            return False
            
        # Check for root privileges when needed
        if self.args.syn_stealth and not self.has_root():
            print(f"{Color.YELLOW}Warning: SYN stealth scan requires root privileges. Falling back to TCP connect scan.{Color.END}")
            self.args.syn_stealth = False
            self.args.tcp_connect = True
            
        return True
        
    def is_valid_cidr(self, cidr):
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(cidr)
            return True
        except ValueError:
            return False
            
    def is_valid_ports(self, port_str):
        """Validate port specification"""
        for part in port_str.split(','):
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if not (0 <= start <= 65535 and 0 <= end <= 65535):
                        return False
                except ValueError:
                    return False
            else:
                try:
                    port = int(part)
                    if not (0 <= port <= 65535):
                        return False
                except ValueError:
                    return False
        return True
        
    def has_root(self):
        """Check for root privileges"""
        import os
        return os.geteuid() == 0
        
    def print_help(self):
        """Print customized help message"""
        print_banner()
        self.parser.print_help()
        
    def get_config_summary(self):
        """Generate human-readable configuration summary"""
        summary = []
        summary.append(f"{Color.CYAN}\n=== Scan Configuration Summary ===")
        summary.append(f"Target: {Color.GREEN}{self.args.target}{Color.CYAN}")
        
        # Scan type
        scan_types = []
        if self.args.syn_stealth: scan_types.append("SYN Stealth")
        if self.args.tcp_connect: scan_types.append("TCP Connect")
        if self.args.udp_scan: scan_types.append("UDP")
        if self.args.ack_scan: scan_types.append("ACK")
        if self.args.fin_scan: scan_types.append("FIN")
        if not scan_types: scan_types.append("TCP Connect (default)")
        summary.append(f"Scan Type: {Color.GREEN}{', '.join(scan_types)}{Color.CYAN}")
        
        # Port specification
        if self.args.top_ports:
            summary.append(f"Ports: {Color.GREEN}Top {self.args.top_ports} ports{Color.CYAN}")
        else:
            summary.append(f"Ports: {Color.GREEN}{self.args.ports}{Color.CYAN}")
            
        # Detection options
        detections = []
        if self.args.service_detection: 
            detections.append(f"Service Detection (intensity {self.args.version_intensity})")
        if self.args.os_detection: detections.append("OS Detection")
        if detections:
            summary.append(f"Detection: {Color.GREEN}{', '.join(detections)}{Color.CYAN}")
            
        # Host discovery
        if self.args.no_ping:
            summary.append(f"Host Discovery: {Color.YELLOW}Disabled{Color.CYAN}")
        else:
            discovery = []
            if self.args.tcp_syn_ping: discovery.append(f"TCP SYN Ping ({self.args.tcp_syn_ping})")
            if self.args.tcp_ack_ping: discovery.append(f"TCP ACK Ping ({self.args.tcp_ack_ping})")
            if self.args.udp_ping: discovery.append(f"UDP Ping ({self.args.udp_ping})")
            if discovery:
                summary.append(f"Host Discovery: {Color.GREEN}{', '.join(discovery)}{Color.CYAN}")
            else:
                summary.append(f"Host Discovery: {Color.GREEN}ICMP Ping{Color.CYAN}")
                
        # Timing
        timing_levels = ["Paranoid", "Sneaky", "Polite", "Normal", "Aggressive", "Insane"]
        summary.append(f"Timing: {Color.GREEN}{timing_levels[self.args.timing]} (T{self.args.timing}){Color.CYAN}")
        
        # Evasion techniques
        evasion = []
        if self.args.fragment: evasion.append("Packet Fragmentation")
        if self.args.decoy: evasion.append(f"Decoys ({self.args.decoy})")
        if self.args.spoof_ip: evasion.append(f"Spoofed IP ({self.args.spoof_ip})")
        if self.args.spoof_mac: evasion.append(f"Spoofed MAC ({self.args.spoof_mac})")
        if self.args.badsum: evasion.append("Invalid Checksums")
        if evasion:
            summary.append(f"Evasion: {Color.YELLOW}{', '.join(evasion)}{Color.CYAN}")
            
        # Output options
        outputs = []
        if self.args.normal_output: outputs.append(f"Normal: {self.args.normal_output}")
        if self.args.xml_output: outputs.append(f"XML: {self.args.xml_output}")
        if self.args.json_output: outputs.append(f"JSON: {self.args.json_output}")
        if self.args.grep_output: outputs.append(f"Grepable: {self.args.grep_output}")
        if outputs:
            summary.append(f"Output: {Color.GREEN}{', '.join(outputs)}{Color.CYAN}")
            
        summary.append(f"Verbosity: {Color.GREEN}{self.args.verbose} level(s){Color.CYAN}")
        summary.append(f"Debugging: {Color.GREEN}{self.args.debug} level(s){Color.CYAN}")
        summary.append("==================================")
        return "\n".join(summary)

if __name__ == "__main__":
    # Test the CLI interface
    cli = RebelCLI()
    args = cli.parse_args()
    
    if args:
        print_banner()
        print(cli.get_config_summary())
        print(f"\n{Color.GREEN}Starting scan with above configuration...{Color.END}")
        # Normally you would launch the scan here
    else:
        cli.print_help()