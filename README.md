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
1. Clone the repository:
```
git clone https://github.com/yourusername/socbot.git
cd socbot
```

2. Install necessary Python dependencies:
```
pip install -r requirements.txt
```

3. Configure the log file path (/var/log/auth.log by default):

Modify the log_file variable in script.py to point to your system's log file, if necessary.



