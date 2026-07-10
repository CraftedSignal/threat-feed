---
title: Unusual Spike in Web Server Error Logs Indicating Reconnaissance Activity
slug: 2024-01-web-server-error-spike
description: An unusual spike in web server error logs may indicate reconnaissance activities such as vulnerability scanning or fuzzing attempts by adversaries probing for weaknesses in web applications.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - reconnaissance
  - web-server
  - vulnerability-scanning
vendors:
  - Nginx
  - Apache Software Foundation
  - Microsoft
products:
  - Nginx
  - Apache HTTP Server
  - Apache Tomcat
  - IIS
mitre_ttps:
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/reconnaissance_web_server_unusual_spike_in_error_logs.toml
  - https://attack.mitre.org/techniques/T1595/
rules:
  - title: Potential Spike in Web Server Error Logs (Single IP)
    description: Detects a spike in web server error logs from a single source IP, indicating potential reconnaissance or scanning activity.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Potential Spike in Web Server Error Logs (Multiple IPs)
    description: Detects a spike in web server error logs across multiple source IPs, indicating potential widespread reconnaissance or scanning activity.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This alert identifies potential reconnaissance activity against web servers by detecting unusual spikes in error logs. Threat actors often utilize vulnerability scanners and fuzzers to identify weaknesses in web applications. These tools generate a high volume of error responses (e.g., 404, 500) as they probe for common vulnerabilities, misconfigurations, and sensitive files/directories. The rule specifically targets web servers running Nginx, Apache, Apache Tomcat, and IIS. Defenders should investigate spikes in error logs to determine the source of the traffic and assess whether the reconnaissance activity was successful in identifying exploitable vulnerabilities. This behavior is often associated with the early stages of an attack. The original rule was created on 2025/11/19 and updated on 2026/04/10.

## Attack Chain

1. The attacker identifies a target web server or application.
2. The attacker deploys a vulnerability scanner or fuzzer against the target.
3. The scanner sends a series of HTTP requests with malicious or malformed input, targeting common vulnerabilities (e.g., path traversal, SQL injection) and sensitive files/directories (e.g., /.env, /.git, /admin).
4. The web server logs error responses (e.g., 404 Not Found, 500 Internal Server Error) due to the malicious requests.
5. The detection rule identifies an unusual spike in the number of error log entries originating from a specific source IP address.
6. The attacker analyzes the error responses to identify potential vulnerabilities or misconfigurations.
7. If a vulnerability is identified, the attacker attempts to exploit it.
8. Upon successful exploitation, the attacker gains unauthorized access to the web server or application.

## Impact

A successful reconnaissance attempt can lead to the discovery of exploitable vulnerabilities in web applications. This can result in unauthorized access to sensitive data, system compromise, or denial of service. While this specific detection triggers on error rate, a successful exploit could lead to full system compromise. The impact depends on the severity of the underlying vulnerabilities and the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule `Potential Spike in Web Server Error Logs` to your SIEM and tune the threshold (currently 50 events) for your environment to reduce false positives.
*   Investigate alerts triggered by the Sigma rule by pivoting on the source IP address and analyzing the error log entries to identify the specific vulnerabilities being targeted.
*   Block or throttle the source IP address at the WAF/CDN and load balancer to mitigate the reconnaissance activity, as mentioned in the overview.
*   Review and harden the web server configuration to address any identified vulnerabilities, such as access to environment files and VCS directories, disabling directory listing, locking down admin consoles, and rejecting unsupported HTTP methods, as described in the alert's remediation guidance.
*   Enable Sysmon process creation logging to detect suspicious child processes spawned by the webserver upon successful exploitation.
*   Monitor webserver logs for successful access (200/302 responses) to sensitive paths or API keys following a spike in error logs.
