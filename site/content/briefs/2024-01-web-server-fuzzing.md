---
title: Web Server Discovery or Fuzzing Activity Detected
slug: 2024-01-web-server-fuzzing
description: Detection of web server discovery or fuzzing activity indicated by a high volume of HTTP GET requests resulting in 404 or 403 status codes originating from a single source IP address within a short timeframe, suggesting attempts to discover hidden resources.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - web-server
  - fuzzing
  - reconnaissance
  - web-application
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
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/reconnaissance_web_server_discovery_or_fuzzing_activity.toml
  - https://attack.mitre.org/techniques/T1595/
rules:
  - title: Web Server Fuzzing Detection
    description: Detects web server fuzzing activity based on a high volume of 403/404 responses from a single IP address.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux|windows
  - title: Web Server Fuzzing - Multiple Status Codes
    description: Detects web server fuzzing with multiple non-200 response codes.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux|windows
rules_count: 2
---

This rule detects potential reconnaissance activity against web servers, specifically web server discovery or fuzzing. The activity is characterized by a single source IP address generating a high volume of HTTP GET requests that result in 404 (Not Found) or 403 (Forbidden) status codes within a short time period. The logic is based on analysis of web server logs from Nginx, Apache, Apache Tomcat, IIS, and Traefik. Such patterns typically indicate an attacker is trying to discover hidden or unlinked resources, potentially identifying vulnerabilities or sensitive information disclosure points on the web server. This discovery phase can often precede more targeted attacks. The detection logic triggers when more than 500 events from a single source IP are observed, involving more than 250 distinct URL requests.

## Attack Chain

1.  The attacker initiates a connection to the target web server using an automated tool.
2.  The attacker sends a large number of HTTP GET requests to the web server, probing various URLs and paths.
3.  The web server responds to the requests, often returning 404 (Not Found) or 403 (Forbidden) status codes for non-existent or restricted resources.
4.  The attacker analyzes the HTTP response codes to identify potentially accessible or vulnerable resources.
5.  If accessible resources are found (e.g., administrative interfaces, backup files), the attacker attempts to access them.
6.  The attacker may attempt further exploitation based on discovered vulnerabilities or accessible resources.
7.  The attacker gains unauthorized access to the web server or sensitive data.
8.  The attacker performs malicious activities such as data theft, defacement, or system compromise.

## Impact

Successful web server discovery and fuzzing can lead to the identification of sensitive files (e.g., configuration files, backups), vulnerable endpoints (e.g., administrative interfaces), and insecure configurations. An attacker can leverage this information to gain unauthorized access, leading to data breaches, system compromise, or service disruption. The severity of the impact depends on the nature of the exposed resources and the attacker's capabilities.

## Recommendation

*   Deploy the Sigma rule `Web Server Fuzzing Detection` to your SIEM and tune the threshold based on your environment's baseline traffic to reduce false positives.
*   Review web server logs for patterns matching the description in the `Overview` to identify potential attackers.
*   Implement rate limiting on your web servers and WAF to mitigate the impact of web server discovery and fuzzing attempts, based on the analysis of `http.request.method` and `http.response.status_code`.
*   Ensure that sensitive files and directories are properly secured and not publicly accessible, reviewing access control configurations on the web server.
*   Monitor web server logs for requests to common sensitive paths (e.g., /.env, /.git, /admin), using a rule targeting the `url.original` field, to detect unauthorized access attempts.
