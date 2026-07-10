---
title: Web Server Local File Inclusion Activity
slug: 2024-01-web-server-lfi
description: This rule detects potential Local File Inclusion (LFI) exploitation on web servers by identifying HTTP GET requests attempting to access sensitive local files through directory traversal or known file paths, potentially leading to sensitive information disclosure.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lfi
  - web-server
  - directory-traversal
  - information-disclosure
vendors:
  - Nginx
  - Apache
  - Microsoft
  - Traefik
products:
  - Nginx
  - Apache
  - Apache Tomcat
  - IIS
  - Traefik
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://attack.mitre.org/techniques/T1083/
rules:
  - title: Web Server Local File Inclusion - Unix
    description: Detects potential Local File Inclusion (LFI) attempts on web servers using Unix-style directory traversal and attempts to access sensitive files.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - web
      - nginx|apache|apache_tomcat|iis|traefik
  - title: Web Server Local File Inclusion - Windows
    description: Detects potential Local File Inclusion (LFI) attempts on web servers using Windows-style directory traversal and attempts to access sensitive files.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - web
      - nginx|apache|apache_tomcat|iis|traefik
rules_count: 2
---

This detection rule, originally created on 2025-12-02 and updated on 2026-03-16, identifies potential Local File Inclusion (LFI) attacks targeting web servers. LFI vulnerabilities allow attackers to read sensitive files on the server, potentially leading to information disclosure, privilege escalation, or further system compromise. This rule focuses on detecting HTTP GET requests that use directory traversal sequences (e.g., `../../../etc/passwd`) or attempt to access known sensitive file paths (e.g., `/proc/self/environ`, `web.config`) on various web server platforms, including Nginx, Apache, Apache Tomcat, IIS, and Traefik. Successful exploitation can expose sensitive configuration files, credentials, and other confidential data. The rule is designed for Elastic Stack version 9.2.0 and later.

## Attack Chain

1.  The attacker identifies a web application endpoint vulnerable to LFI.
2.  The attacker crafts an HTTP GET request with a manipulated URL parameter. The parameter value contains directory traversal sequences (e.g., `../../../`) to navigate the file system.
3.  Alternatively, the attacker crafts an HTTP GET request with a URL containing direct paths to sensitive files, such as `/etc/passwd` or `web.config`.
4.  The web server processes the request and, due to the LFI vulnerability, reads the targeted file.
5.  The web server returns the contents of the file in the HTTP response.
6.  The attacker analyzes the response to extract sensitive information, such as user credentials, configuration details, or internal system information.
7.  The attacker leverages the extracted information to escalate privileges, gain unauthorized access, or further compromise the system. This may include lateral movement or remote code execution.

## Impact

Successful LFI exploitation can lead to the disclosure of sensitive information, including usernames, passwords, API keys, database connection strings, and other confidential data. This information can be used to gain unauthorized access to the web server, escalate privileges, and compromise other systems on the network. Depending on the exposed files, the attacker may gain complete control over the web server and potentially pivot to other internal resources.

## Recommendation

*   Deploy the Sigma rule `WebServerLocalFileInclusionUnix` to your SIEM to detect LFI attempts using Unix-style directory traversal and known file paths in access logs (`logsource.category: web`).
*   Deploy the Sigma rule `WebServerLocalFileInclusionWindows` to your SIEM to detect LFI attempts using Windows-style directory traversal and known file paths in access logs (`logsource.category: web`).
*   Block GET requests using directory traversal or wrappers (php://, expect://, data://) fetching /etc/passwd, /proc/self/environ, wp-config.php, web.config, or applicationhost.config as suggested in the investigation guide.
*   Enable URL decoding in your web application firewall (WAF) to normalize URLs and block traversal attempts as per the remediation steps in the overview.
