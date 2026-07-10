---
title: Web Server Local File Inclusion Activity Detected
slug: 2024-01-29-web-server-lfi
description: Detection of potential Local File Inclusion (LFI) activity on web servers through HTTP GET requests attempting to access sensitive local files via directory traversal or known file paths, potentially leading to information disclosure and system compromise.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - web-server
  - lfi
  - file-inclusion
  - discovery
  - credential-access
  - initial-access
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
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://attack.mitre.org/techniques/T1083/
  - https://attack.mitre.org/techniques/T1005/
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1552/001/
  - https://attack.mitre.org/techniques/T1190/
rules:
  - title: Web Server Local File Inclusion - Directory Traversal
    description: Detects attempts to exploit Local File Inclusion vulnerabilities through directory traversal sequences in HTTP GET requests.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1083
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Web Server Local File Inclusion - Sensitive File Access
    description: Detects attempts to access sensitive files via HTTP GET requests, indicative of Local File Inclusion exploitation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
      - initial_access
    techniques:
      - T1005
      - T1190
      - T1552
    data_sources:
      - webserver
      - linux
  - title: Web Server Local File Inclusion - Protocol Wrappers
    description: Detects attempts to use protocol wrappers in HTTP GET requests, indicative of Local File Inclusion exploitation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
      - initial_access
    techniques:
      - T1005
      - T1190
      - T1552
    data_sources:
      - webserver
      - linux
rules_count: 3
---

This rule identifies potential Local File Inclusion (LFI) attempts against web servers. LFI is a vulnerability that allows attackers to read arbitrary files on a server, potentially exposing sensitive information such as credentials, configuration details, and source code. The detection focuses on HTTP GET requests containing directory traversal sequences (e.g., `../../../etc/passwd`) or direct attempts to access sensitive files (e.g., `/proc/self/environ`, `web.config`). The rule covers various web servers including Nginx, Apache, Apache Tomcat, IIS, and Traefik. It aims to detect initial reconnaissance and exploitation attempts targeting common configuration files and system information. Successful exploitation can lead to credential access and further system compromise. This rule was last updated on 2026/04/10 and requires Elastic stack version 9.2.0 or higher.

## Attack Chain

1.  The attacker identifies a web application with a potential LFI vulnerability.
2.  The attacker crafts a malicious HTTP GET request containing directory traversal sequences (e.g., `../../../etc/passwd`) within a URL parameter.
3.  The web server processes the request, and due to the LFI vulnerability, attempts to read the file specified by the attacker's input.
4.  If successful, the contents of the targeted file (e.g., `/etc/passwd`, `web.config`) are included in the HTTP response.
5.  The attacker analyzes the response to extract sensitive information, such as user credentials, API keys, or database connection strings.
6.  The attacker may leverage the gathered information to escalate privileges or move laterally within the network.
7.  The attacker may attempt to read `/proc/self/environ` to gather environmental variables, potentially revealing further sensitive information.
8.  The attacker uses exfiltrated credentials to gain unauthorized access to other systems and resources.

## Impact

Successful LFI exploitation can lead to the disclosure of sensitive information, including system credentials, configuration files, and potentially even source code. This could allow attackers to gain unauthorized access to systems, escalate privileges, or compromise sensitive data. Exposed credentials from configuration files (like `wp-config.php`, `web.config`, or `applicationhost.config`) can be used to compromise databases, APIs, and other critical infrastructure. In severe cases, attackers might be able to achieve remote code execution by exploiting further vulnerabilities based on the information gathered through LFI.

## Recommendation

*   Deploy the Sigma rule `Web Server Local File Inclusion - Directory Traversal` to detect attempts to use directory traversal sequences in HTTP GET requests.
*   Deploy the Sigma rule `Web Server Local File Inclusion - Sensitive File Access` to detect direct attempts to access sensitive files.
*   Review web server access logs for HTTP GET requests with a status code of 200 and containing directory traversal or sensitive file paths (as described in the Overview).
*   Implement input validation and sanitization measures to prevent LFI vulnerabilities in web applications. Specifically, canonicalize input, reject ".. "segments, enforce whitelists, and disable `allow_url_include/allow_url_fopen` in PHP.
*   Configure web servers to restrict access to sensitive files and directories (e.g., `/etc`, `/proc`, `/var/log`, `/inetpub`) by returning a 403 Forbidden error.
*   Monitor web server error logs for include/open stream warnings related to attempted file access, as mentioned in the investigation guide.
