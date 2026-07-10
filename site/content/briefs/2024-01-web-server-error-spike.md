---
title: Web Server Error Response Spike Indicates Reconnaissance
slug: 2024-01-web-server-error-spike
description: A surge in 500-level HTTP error codes on web servers may indicate reconnaissance activities such as vulnerability scanning or fuzzing, where attackers probe for weaknesses by generating numerous error responses.
date: "2024-01-09T12:00:00Z"
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
  - Apache
  - Microsoft
  - Traefik Labs
products:
  - Nginx
  - Apache
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
  - https://attack.mitre.org/techniques/T1595/
  - https://attack.mitre.org/techniques/T1595/002/
  - https://attack.mitre.org/techniques/T1595/003/
rules:
  - title: Web Server Unusual Spike in 5XX Errors
    description: Detects a spike in 5XX HTTP error codes, indicative of potential scanning or fuzzing attempts
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
      - T1595.002
      - T1595.003
    data_sources:
      - webserver
      - nginx|apache|apache_tomcat|iis|traefik
  - title: Web Server Fuzzing Attempt via URL
    description: Detects a high number of 5XX HTTP errors from a single source IP targeting various URL paths
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595
      - T1595.002
      - T1595.003
    data_sources:
      - webserver
      - nginx|apache|apache_tomcat|iis|traefik
rules_count: 2
---

This detection focuses on identifying potential reconnaissance activities against web servers by monitoring spikes in HTTP error response codes (500, 502, 503, 504). Attackers often employ vulnerability scanners and fuzzers to probe web applications for weaknesses. These tools generate a high volume of requests, many of which result in server-side errors as they explore various attack vectors. This can also expose fragile code paths or misconfigured proxies. The rule analyzes GET requests specifically, targeting anomalies in error code frequency originating from single source IPs. The monitored web servers include Nginx, Apache, Apache Tomcat, IIS, and Traefik. This activity matters to defenders because successful reconnaissance can precede exploitation, data breaches, or denial-of-service attacks.

## Attack Chain

1.  Attacker initiates a vulnerability scan or fuzzing campaign against a target web server.
2.  The scanning tool sends a series of GET requests with potentially malicious payloads or malformed URLs.
3.  The web server encounters errors while processing these requests due to invalid input or resource unavailability.
4.  The web server responds with HTTP error codes (500, 502, 503, or 504).
5.  These error responses are logged by the web server, including source IP, requested URL, and status code.
6.  The attacker analyzes the error responses to identify potential vulnerabilities or misconfigurations.
7.  The attacker refines their attack strategy based on the information gathered from the error responses.
8.  The attacker attempts to exploit identified vulnerabilities for unauthorized access or information disclosure.

## Impact

An attacker performing active scanning or fuzzing can uncover sensitive information about a web application's configuration and vulnerabilities. Successful reconnaissance can lead to exploitation, data breaches, or denial-of-service attacks. While a spike in error codes alone may not indicate a successful compromise, it serves as an early warning sign of potentially malicious activity. If successful, attackers enumerate routes to find inputs to crash components for follow-on exploitation.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect unusual spikes in HTTP error responses and tune for your environment.
*   Investigate any alerts triggered by the Sigma rules to determine the source of the error responses and the nature of the requests (reference the "Investigation Guide" tag in the original rule).
*   Implement rate limiting or blocking at the edge (reverse proxy/WAF) for clients generating excessive error responses (reference the description).
*   Harden web server configurations to prevent information leakage in error messages and mitigate potential vulnerabilities (reference the description).
