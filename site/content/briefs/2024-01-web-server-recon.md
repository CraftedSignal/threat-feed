---
title: Web Server Reconnaissance via Suspicious User Agents
slug: 2024-01-web-server-recon
description: Attackers use automated tools with suspicious user agents to perform reconnaissance against web servers, attempting to identify vulnerabilities and hidden paths for further exploitation.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - web-server
  - reconnaissance
  - vulnerability-scanning
vendors:
  - Nginx
  - Apache Software Foundation
  - Microsoft
  - Traefik Labs
products:
  - Nginx
  - Apache HTTP Server
  - Apache Tomcat
  - Internet Information Services
  - Traefik
mitre_ttps:
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/reconnaissance_web_server_unusual_user_agents.toml
rules:
  - title: Detect Web Server Reconnaissance User Agents
    description: Detects requests with User-Agent strings commonly associated with web application scanners.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume Requests from Single IP with Scanner User Agent
    description: Detects unusual spikes in web server requests with scanner User-Agent strings from a single IP address
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

This brief focuses on detecting reconnaissance attempts against web servers through the use of suspicious user agents. Attackers often employ automated tools like Dirsearch, Gobuster, WPScan, and SQLMap to scan web applications for vulnerabilities, hidden directories, and sensitive files. These tools send a high volume of requests with specific user-agent strings associated with scanning or brute-force activity. The activity is identified by observing requests from IPs with a high number of requests and distinct URLs, using unusual User-Agent header values. This activity indicates potential reconnaissance, which may lead to more serious attacks if vulnerabilities are discovered. This rule focuses on detecting this behavior across Nginx, Apache, Apache Tomcat, IIS, and Traefik web servers.

## Attack Chain

1. The attacker deploys a web application scanner such as Dirsearch, WPScan, or Gobuster.
2. The scanning tool sends HTTP GET requests to the target web server with a crafted User-Agent header.
3. The User-Agent header identifies the scanning tool (e.g., "dirsearch", "wpscan").
4. The scanner iterates through a list of common or custom URLs and file paths, looking for accessible resources.
5. The web server logs each request, including the source IP, User-Agent, and requested URL.
6. The attacker analyzes the server responses, looking for indications of sensitive files, directories, or vulnerabilities.
7. Discovery of sensitive resources (e.g., configuration files, admin panels) enables further exploitation.
8. The attacker pivots to exploiting identified vulnerabilities or accessing sensitive data.

## Impact

Successful reconnaissance can expose sensitive information, such as configuration files, database credentials, or administrative interfaces. This information can be used to gain unauthorized access to the web server or the underlying system. While this activity on its own is low severity, successful exploitation following reconnaissance can lead to data breaches, system compromise, and reputational damage. The broad targeting capabilities of these tools mean that any organization running web servers is potentially at risk.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect suspicious User-Agent strings in web server logs (e.g., "dirsearch", "sqlmap", "nikto") and tune for your environment.
*   Monitor web server logs (Nginx, Apache, IIS) for unusual spikes in requests with suspicious User-Agent headers to activate the Sigma rules.
*   Implement rate limiting on web servers to mitigate the impact of high-volume scanning activity, specifically referencing the detection logic in the Sigma rules.
*   Block IPs identified as sources of suspicious User-Agent requests at the firewall or WAF based on the source IP identified in the Sigma rules.
