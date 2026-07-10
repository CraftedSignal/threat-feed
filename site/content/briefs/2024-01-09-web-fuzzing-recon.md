---
title: Web Server Discovery or Fuzzing Activity Detection
slug: 2024-01-09-web-fuzzing-recon
description: This rule detects potential web server discovery or fuzzing activity by identifying a high volume of HTTP GET requests resulting in 404 or 403 status codes from a single source IP address within a short timeframe, indicating attackers discovering hidden resources for targeted attacks.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - web-server
  - fuzzing
  - reconnaissance
  - web
vendors:
  - Nginx
  - Apache
  - Microsoft
  - Traefik Labs
products:
  - Nginx
  - Apache HTTP Server
  - Apache Tomcat
  - IIS
  - Traefik
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
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/reconnaissance_web_server_discovery_or_fuzzing_activity.toml
  - https://attack.mitre.org/techniques/T1595/
  - https://attack.mitre.org/techniques/T1595/002/
  - https://attack.mitre.org/techniques/T1595/003/
  - https://attack.mitre.org/tactics/TA0043/
rules:
  - title: Web Server Fuzzing Activity - High Volume
    description: Detects a high volume of 404 or 403 HTTP responses from a single source IP address, indicating potential web server fuzzing or discovery activity.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
      - T1595.003
    data_sources:
      - network_connection
      - nginx|apache|apache_tomcat|iis|traefik
  - title: Web Server Fuzzing Activity - Distinct URLs
    description: Detects a high number of distinct URLs requested from a single source IP address resulting in 404 or 403, indicating a web server fuzzing attempt.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595
      - T1595.003
    data_sources:
      - web
      - nginx|apache|apache_tomcat|iis|traefik
rules_count: 2
---

This detection rule identifies potential web server discovery or fuzzing activity. Attackers often employ automated tools to discover hidden or unlinked resources on a web server. This reconnaissance phase involves sending a high volume of HTTP GET requests, often resulting in 404 (Not Found) or 403 (Forbidden) status codes. The rule focuses on identifying a single source IP address generating a large number of such requests within a defined timeframe. The targeted web servers can be running Nginx, Apache, Apache Tomcat, IIS, or Traefik. Detecting this activity early can prevent more targeted attacks by identifying and blocking malicious sources before they discover sensitive information or vulnerabilities. This proactive approach helps maintain the security and integrity of web applications and infrastructure.

## Attack Chain

1.  **Initial Reconnaissance:** The attacker begins by identifying potential target web servers.
2.  **Tool Selection:** The attacker chooses a web server discovery or fuzzing tool.
3.  **Request Generation:** The attacker uses the selected tool to generate a high volume of HTTP GET requests.
4.  **Resource Enumeration:** The tool iterates through a list of potential resource paths and sends GET requests to each.
5.  **Status Code Analysis:** The attacker analyzes the HTTP response codes to identify resources that return 404 or 403 status codes, indicating non-existent or forbidden paths.
6.  **Discovery of Hidden Resources:** The attacker identifies potentially vulnerable or misconfigured resources based on the responses.
7.  **Targeted Exploitation:** The attacker focuses on the discovered resources, attempting to exploit vulnerabilities or gain unauthorized access.
8.  **Impact:** Successful exploitation can lead to data breaches, system compromise, or other malicious activities.

## Impact

Successful web server discovery and fuzzing can lead to the identification of sensitive files, misconfigured directories, and exploitable vulnerabilities. While this rule is rated as low severity, successful reconnaissance paves the way for more severe attacks. Exploitation of discovered vulnerabilities could lead to data breaches, unauthorized access, and denial-of-service attacks. The number of victims can vary depending on the scale and nature of the targeted web application. Sectors commonly targeted include e-commerce, banking, and government.

## Recommendation

*   Deploy the Sigma rule `Web Server Fuzzing Activity - High Volume` to your SIEM to detect suspicious IP addresses generating a high number of 404/403 responses (rule definition below).
*   Review web server logs for anomalies and unexpected 404/403 responses, focusing on the IP addresses flagged by the `Web Server Fuzzing Activity - High Volume` rule.
*   Implement rate limiting on web servers to mitigate the impact of fuzzing attempts.
*   Monitor authentication logs for unusual patterns following the detection of web server fuzzing to catch potential exploitation attempts (related to the investigation steps).
*   Block identified malicious IP addresses at the firewall or WAF (based on source.ip in the rule definition).
*   Enable comprehensive web server logging, including request methods, URLs, and response codes, to enhance detection capabilities.
