---
title: Web Server Potential Remote File Inclusion Activity
slug: 2024-01-rfi-discovery
description: This rule detects potential Remote File Inclusion (RFI) activity on web servers by identifying HTTP GET requests that attempt to access sensitive remote files through directory traversal techniques or known file paths, potentially leading to information disclosure or further compromise.
date: "2024-01-09T18:22:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - rfi
  - webserver
  - vulnerability
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
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://attack.mitre.org/techniques/T1083/
  - https://attack.mitre.org/techniques/T1190/
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/discovery_web_server_remote_file_inclusion_activity.toml
rules:
  - title: Web Server Potential Remote File Inclusion Activity
    description: Detects potential Remote File Inclusion (RFI) activity on web servers based on HTTP GET requests with parameters containing remote URLs or raw IPs.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - discovery
      - initial_access
    techniques:
      - T1083
      - T1190
    data_sources:
      - webserver
      - nginx|apache|apache_tomcat|iis|traefik
  - title: Web Server RFI via URL Encoding
    description: Detects RFI attempts where the malicious URL is encoded within the request.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - discovery
      - initial_access
    techniques:
      - T1083
      - T1190
    data_sources:
      - webserver
      - nginx|apache|apache_tomcat|iis|traefik
rules_count: 2
---

This detection rule identifies potential Remote File Inclusion (RFI) attacks targeting web servers. RFI vulnerabilities allow attackers to inject malicious code by including remote files into the web server's application. The rule focuses on detecting HTTP GET requests with a 200 OK status code that contain suspicious URL parameters. These parameters attempt to access sensitive remote files using directory traversal techniques or directly specifying known file paths. This activity can lead to unauthorized access to sensitive information, system information disclosure, or further server compromise. The rule covers web servers like Nginx, Apache, Apache Tomcat, IIS, and Traefik. This activity is important for defenders to detect, as it can lead to significant data breaches and system compromise.

## Attack Chain

1.  Attacker identifies a vulnerable web server endpoint that is susceptible to RFI.
2.  The attacker crafts a malicious HTTP GET request. This request includes a URL parameter (e.g., `page=`, `url=`, `src=`) with a URL pointing to a remote file or IP address controlled by the attacker. The URL can also leverage wrappers like `php://`, `data://`, or `file://`.
3.  The victim web server receives the malicious GET request.
4.  The web server processes the request and attempts to include the remote file specified in the URL parameter.
5.  If the web server is vulnerable, it successfully fetches the content from the attacker-controlled remote server.
6.  The attacker's malicious code or script within the included file is executed within the context of the web server.
7.  The attacker gains unauthorized access to the web server's file system, configuration files, or sensitive data.
8.  The attacker can then escalate privileges, install malware, or exfiltrate sensitive data.

## Impact

Successful RFI attacks can lead to severe consequences, including unauthorized access to sensitive data, system compromise, and potential data breaches. Attackers can leverage RFI to read configuration files, gain access to credentials, and execute arbitrary code on the web server. This could result in the loss of confidential information, disruption of services, or the complete takeover of the affected system. The impact of a successful RFI attack can range from information disclosure to full system compromise, depending on the severity of the vulnerability and the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule "Web Server Potential Remote File Inclusion Activity" to your SIEM to detect suspicious GET requests containing remote URLs (see rules section).
*   Inspect web server logs (Nginx, Apache, Apache Tomcat, IIS, and Traefik) for GET requests with status code 200 containing parameters with encoded URLs or raw IPs.
*   Implement and tune WAF rules to block suspicious include parameters (e.g., `page=`, `url=`, or `src=`) containing `http://`, `https://`, `ftp://`, `smb://`, or `file://`.
*   Restrict outbound connections from web servers to known, trusted domains to prevent exploitation of RFI vulnerabilities.
*   Set PHP `allow_url_include=Off` and `allow_url_fopen=Off` in PHP configuration files to mitigate RFI vulnerabilities.
*   Apply `open_basedir` restrictions in PHP to limit the files that PHP scripts can access.
