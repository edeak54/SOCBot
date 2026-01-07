# SOCBot
SOCBot is a lightweight, automated log monitoring and response system designed to keep your system secure with minimal setup and configuration. Built to detect suspicious activity, respond in real-time, and block malicious IPs, SOCBot brings an extra layer of protection to your server environment by continuously monitoring authentication logs for anomalies.

# Features 🚨 
***Real-Time Monitoring**: SOCBot reads and processes log entries in real-time, ensuring no malicious activity goes unnoticed.


***Automated Threat Detection**: SOCBot uses a set of predefined rules to automatically detect:
- Failed login attempts
- Brute force attacks
- Sudo authentication failures
- Unusual root login attempts
- Potential security vulnerabilities (e.g., buffer overflows, system reboots)


***Instant Response**: On detecting suspicious activity, SOCBot takes immediate action, including:
- Blocking malicious IPs: Automatically blocks IP addresses attempting brute force or unauthorized access.
- Alert Logging: Logs detailed security alerts to keep you informed about every suspicious event.


***Customizable & Extendable**: SOCBot's rule-based structure allows you to easily extend and customize it to match your security needs.

# Setup ⚙️
### Requirements:
* Python 3.x
* iptables (for blocking IPs)
* Access to authentication logs (typically /var/log/auth.log on Linux systems)


# Installation
1. **Clone the repository**:
```
git clone https://github.com/edeak54/socbot.git
cd socbot
```
##
2. **Install necessary Python dependencies**:
```
pip install -r requirements.txt
```
##
3. **Configure the log file path (/var/log/auth.log by default)**:

Modify the log_file variable in script.py to point to your system's log file, if necessary.
##
4. **Run the monitoring script**:
```
python3 socbot.py
```
The bot will now continuously monitor logs for suspicious activity and respond accordingly!
##

# How It Works 🛡️ 
SOCBot works by continuously reading through system logs (such as /var/log/auth.log) and applying predefined detection rules. Upon detecting any suspicious log entry (e.g., a failed login or unusual sudo command), SOCBot immediately takes the corresponding action, such as blocking the IP address or logging an alert.
### Key Rules:
* **Failed Login Attempts**: If there are multiple failed login attempts from the same IP within a short time window, SOCBot blocks the IP to prevent brute force attacks.
* **Sudo Failures**: SOCBot watches for unusual sudo authentication failures, which may indicate unauthorized privilege escalation attempts.
* **Root Logins**: Any root login attempt is flagged as suspicious and logged.
* **Buffer Overflows**: SOCBot can detect potential security issues such as buffer overflows based on specific log patterns.

### Automated Response:
* **IP Blocking**: SOCBot uses iptables to block malicious IP addresses.
* **Alerts**: SOCBot logs all suspicious activity, keeping you informed of security risks.

# Customizing SOCBot 🔧 
SOCBot's functionality is driven by rules. Each rule monitors a specific log pattern and triggers an action when the pattern is matched. You can add, modify, or remove rules by updating the rules list in script.py.

Each rule has two components:

* **Pattern**: A regular expression to match specific log entries.
* **Action**: A function that takes action when a match is found (e.g., blocking the IP or logging an alert).


