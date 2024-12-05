import os
import re
import subprocess
import time

# SOCBot : Simple Automated Log Monitoring and Response System

class SOCBot:
    def __init__(self, log_file):
        self.log_file = log_file
        self.alerts = []  
        self.failed_attempts = {}  
        self.logged_ips = {}  
        self.blocked_ips = set()  

        # Rules for monitoring logs
        self.rules = [
            # Failed password attempts (just log the failed attempts, do NOT block)
            {"pattern": r"Failed password for.*from (\d+\.\d+\.\d+\.\d+)", "action": self.log_failed_attempt},
            
            # sudo authentication failure
            {"pattern": r"sudo:.*authentication failure", "action": self.log_alert},
            
            # Too many failed login attempts from the same IP within a short period (CHECKING RATE)
            {"pattern": r"Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)", "action": self.check_failed_attempts_rate},

            # Successful login (Log alert on any successful login)
            {"pattern": r"Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)", "action": self.log_successful_login},

            # Root login attempts (alert if there's a root login)
            {"pattern": r"Accepted password for root from (\d+\.\d+\.\d+\.\d+)", "action": self.log_alert}, 

            # Detection of potential buffer overflow (malicious behavior) from a specific string in logs
            {"pattern": r"Segfault at.* in .*", "action": self.log_alert},
            
            # System boot information (alert if an unusual reboot time is detected)
            {"pattern": r"System boot.*", "action": self.log_alert},
            
            # Unsuccessful `sudo` usage without authentication failure message (sometimes a misconfigured system)
            {"pattern": r"sudo: (?!.*authentication failure).*", "action": self.log_alert},
            
            # RPassword changed (not authorized)
            {"pattern": r"passwd:.*password changed for (\w+)", "action": self.log_alert}
        ]

    def block_ip(self, ip):
        if ip and ip not in self.blocked_ips:
            try:
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                print(f"[ACTION TAKEN] Blocked IP: {ip}")
                self.alerts.append(f"Blocked IP: {ip}")
                self.blocked_ips.add(ip)
            except Exception as e:
                print(f"[ERROR] Failed to block IP: {ip}. Error: {e}")
        elif ip:
            print(f"[INFO] IP {ip} is already blocked.")
        else:
            print("[ERROR] Invalid IP address detected. Skipping blocking action.")

    def log_alert(self, match):
        alert = f"[ALERT] Suspicious activity detected: {match.group(0)}"
        print(alert)
        self.alerts.append(alert)

    def log_failed_attempt(self, match):
        ip = match.group(1)
        if ip in self.blocked_ips:
            print(f"[INFO] IP {ip} is already blocked. Skipping failed attempt log.")
            return
        print(f"[INFO] Failed login attempt detected from IP: {ip}")
        self.alerts.append(f"Failed login attempt from IP: {ip}")

    def log_successful_login(self, match):
        ip = match.group(2)  
        if ip not in self.logged_ips:
            print(f"[ALERT] Successful login detected from IP: {ip}")
            self.logged_ips[ip] = True
            self.alerts.append(f"Successful login detected from IP: {ip}")
        else:
            print(f"[INFO] Successful login from {ip} already recorded.")

    def check_failed_attempts_rate(self, match):
        ip = match.group(3)  

        if ip in self.blocked_ips:
            print(f"[INFO] IP {ip} is already blocked. Skipping failed attempts check.")
            return

        current_time = time.time()

        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []

        self.failed_attempts[ip].append(current_time)

        self.failed_attempts[ip] = [attempt for attempt in self.failed_attempts[ip] if current_time - attempt <= 60]

        print(f"Failed attempts for {ip}: {len(self.failed_attempts[ip])} within 60 seconds.")

        if len(self.failed_attempts[ip]) >= 5:
            print(f"[INFO] 5 or more failed attempts detected for IP {ip}. Blocking...")
            self.block_ip(ip)

    def monitor_logs(self):
        with open(self.log_file, "r") as file:
            file.seek(0, os.SEEK_END)  
            print(f"[INFO] Monitoring {self.log_file} for suspicious activity...")

            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                for rule in self.rules:
                    match = re.search(rule["pattern"], line)
                    if match:
                        if match.lastgroup == 3:
                            ip = match.group(3)
                        else:
                            ip = None

                        if ip in self.blocked_ips:
                            print(f"[INFO] IP {ip} is already blocked. Skipping further processing.")
                            continue 

                        if "action" in rule and callable(rule["action"]):
                            rule["action"](match)

if __name__ == "__main__":
    log_file = "/var/log/auth.log" # Default path is /var/log/auth.log
    if os.path.exists(log_file):
        bot = SOCBot(log_file)
        bot.monitor_logs()
    else:
        print(f"[ERROR] Log file {log_file} does not exist. Please provide a valid path.")
