# ================ exporter.py ================
from datetime import datetime
import json
import csv

def export_json(results, filename):
    with open(filename, 'w') as f:
        json.dump({
            "scan_time": datetime.now().isoformat(),
            "results": results
        }, f, indent=2)

def export_csv(results, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Host', 'Port', 'Status', 'Service'])
        for host, ports in results.items():
            for port, data in ports.items():
                writer.writerow([host, port, data['status'], data['service']])
