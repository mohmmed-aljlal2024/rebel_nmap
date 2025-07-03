"""
RebelNmap - Advanced Network Scanning Toolkit
"""
__version__ = "1.0.0"
__author__ = "Your Name"
__license__ = "GPL-3.0"

# Import key components for easier access
from .scanner import PortScanner
from .host_discovery import HostDiscovery
from .os_detection import OSDetector
from .exporter import export_json, export_csv
from .cli import RebelCLI
from .credential_harvester import activate , CredentialHarvester
# Define public API
__all__ = [
    'PortScanner',
    'HostDiscovery',
    'OSDetector',
    'export_json',
    'export_csv',
    'RebelCLI',
    'CredentialHarvester',
    'activate'
]