# TryHackMe — Log Analysis with SIEM

**Completed:** 10/15/2026

## Overview
In this room I learned how a SOC analyst uses a SIEM (Splunk) to detect and analyse malicious behaviour. I practiced searching host, network, and web logs with Splunk queries, and investigated realistic scenarios such as brute force, privilege escalation, persistence, web shells, and DDoS.

## Learning Objectives
- Discover various data sources that are ingested into a SIEM
- Understand the importance of data correlation
- Learn the value of Windows, Linux, web, and network logs during an investigation
- Practice analysing malicious behaviour

## Key Concepts

### Why SIEM Matters for a SOC
- **Centralisation:** all logs (network devices, cloud, identity providers, endpoints) are in one place, so the analyst does not switch between systems. An analyst with a SIEM investigates faster than one who must log in to each system (IPS, EDR) separately.
- **Correlation:** linking separate events like puzzle pieces. Example: an IDS alert shows only an IP address, and correlating it with identity, system, and network logs reveals the user, the host, and the tool used.
- **Historical events:** looking at past logs to spot patterns that started earlier, such as checking if a user ever logged in from an unusual location before.

### Log Sources Overview
- **Host-based:** workstations and servers (authentication, account management, process auditing, system events, policy changes, object access). Helps detect brute force, account manipulation for persistence, malicious script execution, and unauthorised access to sensitive data.
- **Network-based:** firewall, IDS/IPS, router, VPN, DNS, and proxy logs. Helps detect port scanning, suspicious connections to unusual ports, and unexpected logins.
- **Web-based:** web server, WAF, API gateway, CDN, load balancer, and web app logs. Helps detect web shells and SQL injection attempts.
- **Time pitfalls:** logs can come in different time zones (UTC, local, or none), so the SIEM time can differ from my local time. Always check the time zone when analysing events.
- **Normalisation:** logs come in different formats (JSON, XML, plain text), and the SIEM converts them into one consistent structure so searching and correlation are easier.

### Windows Logs

**Sysmon**
- Detect malicious process execution: search EventCode=1 for PowerShell with an encoded command, then check the parent process, user, and command line.
```
index=winenv EventCode=1 *powershell* AND *EncodedCommand*
| table _time ComputerName ParentUser ParentImage ParentCommandLine Image CommandLine
```
- Detect suspicious network connections: search EventCode=3 filtered by host, and look at the process image, destination IP, and unusual destination port.
```
index=winenv EventCode=3 ComputerName=<host>
| table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol
```

**Windows Security logs**
- Detect account creation/enabling (persistence) with Event IDs 4720 and 4722.
```
index=winenv EventCode=4720 OR EventCode=4722
| table _time EventCode ComputerName Subject_Account_Name Target_Account_Name New_Account_Account_Name Keywords
```

**Windows System logs**
- Detect service-based persistence or privilege escalation with Event IDs 7045 (service created) and 7036 (service started/stopped). A suspicious service running a file from a Temp folder under SYSTEM is a sign of privilege escalation.
```
index=winenv EventCode=7045 OR EventCode=7036 ComputerName=<host>
| table _time EventCode ComputerName Service_Name Service_Account Service_File_Name Message
```

### Linux Logs
- **auth.log:** authentication activity (logins, sudo usage). Useful for failed logins, unauthorised access, and privilege escalation.
- **syslog:** general system events (service restarts, cron jobs, background processes). Useful for building timelines and finding persistence.

**Unusual SSH logins (possible brute force):**
```
index=linux source="auth.log" *ubuntu* process=sshd
| search "Accepted password" OR "Failed password"
```
Many failed logins followed by a successful one from the same IP is a sign of a successful brute force attack that should be escalated to L2.

**Privilege escalation:**
```
index=linux source="auth.log" *su*
| sort + _time
```
Shows `sudo su` execution and a root session being opened.

**Persistence (cron jobs and reverse shells):**
```
index=linux sourcetype=syslog ("CRON" OR "cron")
| search ("python" OR "perl" OR "ruby" OR ".sh" OR "bash" OR "nc")
```
Can reveal a suspicious script in `/tmp` running via cron, or a reverse shell attempting to connect out.

### Web Application Logs
Web access logs show scanning, DDoS, web attacks, and web shells.

**Brute force activity:** filter POST requests to the login page (`/wp-login.php`), group by client IP in 5-minute bins, and set a threshold (count > 25). The User-Agent can reveal the tool used (for example, Hydra).
```
index=* method=POST uri_path="/wp-login.php"
| bin _time span=5m
| stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
| where count > 25
| table referer_domain clientip UserAgent uri_path count status
```

**Possible web shell:** search for requests to script or executable files (`.php`, `.asp`, `.jsp`, `.exe`) with status 200 and POST/GET methods, then investigate suspicious URIs closely.

**DDoS activity:** look for status 503 (server overloaded) with a very high number of requests in a short time (for example, more than 100,000 in 10 minutes per IP).
```
index=* status=503
| bin _time span=10m
| stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
| where count > 100000
| table _time referer_domain clientip UserAgent uri_path count status
```

## Practice Scenarios
I investigated four scenarios in Splunk, each in its own index:
- **Windows (WIN-105):** suspicious network connection on an unusual port. I found the destination IP, the process that started the connection, its hash, and a scheduled task created on the system.
- **Linux (Ubuntu server):** possible persistence through a new SSH user. I traced the account creation, the user who escalated to root, the source IP of the login, the failed attempts before it, and the port of the persistence mechanism.
- **Web server:** a spike in activity. I found the most requested URI, the source IP, classified the activity, and identified the tool used.

## What I Learned
- A SIEM helps by centralising logs, correlating events, and keeping historical data, which makes triage much faster.
- Different log sources answer different questions: host logs show what ran on a machine, network logs show who connected to what, and web logs show attacks on applications.
- Time zones can make events look hours off, so I should always check the time zone first.
- Normalisation lets me search logs from different sources with the same field names.
- Splunk queries are built from simple parts: index, event code or field filters, `stats`, `where` for thresholds, and `table` to show only useful fields.
- Event IDs I should remember: Sysmon 1 (process creation) and 3 (network connection), Security 4720/4722 (account created/enabled), System 7045/7036 (service created/started).
- A single log is often harmless, but correlating process, network, account, and service events tells the full attack story.

## Screenshot
![Room completed](room-completed.png)
