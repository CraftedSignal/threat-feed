---
title: Web Server Local File Inclusion Activity
slug: 2026-07-web-server-local-file-inclusion
description: This brief details how attackers exploit Local File Inclusion (LFI) vulnerabilities on web servers such as Nginx, Apache, IIS, and Traefik, by using directory traversal or direct sensitive file path requests to disclose system information, credentials, and configuration files, potentially leading to remote code execution and system compromise.
date: "2026-07-20T13:06:27Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - local-file-inclusion
  - web-vulnerability
  - information-disclosure
  - remote-code-execution
  - discovery
vendors:
  - Nginx
  - Apache Software Foundation
  - Microsoft
  - Traefik Labs
products:
  - Nginx
  - Apache HTTP Server
  - Apache Tomcat
  - IIS
  - Traefik
affected_os:
  - Linux
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This rule detects potential Local File Inclusion (LFI) activity on web servers by identifying HTTP GET requests that attempt to access sensitive local files through directory traversal techniques or known file paths.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers may exploit LFI vulnerabilities to read sensitive files, gain system information, or further compromise the server.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This rule surfaces successful GET requests containing directory traversal or direct access to sensitive paths, signaling Local File Inclusion exploitation that can expose credentials, configuration, and process context.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This rule detects potential Local File Inclusion (LFI) activity on web servers by identifying HTTP GET requests that attempt to access sensitive local files through directory traversal techniques or known file paths. Attackers may exploit LFI vulnerabilities...
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/discovery_web_server_local_file_inclusion_activity.toml
rules:
  - title: Detect Web Server Local File Inclusion Activity
    description: Detects potential Local File Inclusion (LFI) attempts on web servers by identifying HTTP GET requests with directory traversal patterns, sensitive file paths, or protocol wrappers.
    platform: sigma
    severity: low
    tactics:
      - collection
      - credential_access
      - discovery
      - initial_access
    techniques:
      - T1005
      - T1083
      - T1190
      - T1552
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
---

This brief details a common web server vulnerability, Local File Inclusion (LFI), which attackers exploit to access sensitive information or potentially achieve remote code execution. The Elastic detection rule, published in July 2026, identifies LFI activity by monitoring HTTP GET requests that use directory traversal techniques or directly target known sensitive file paths. These attempts often aim to retrieve critical system files like `/etc/passwd`, `/proc/self/environ`, or `wp-config.php`, and can involve various protocol wrappers such as `php://` or `data://`. Successful exploitation of LFI on web servers running Nginx, Apache, Apache Tomcat, IIS, or Traefik can lead to the exposure of credentials, configuration data, and system context, paving the way for further compromise including webshell deployment or full system takeover.

## Attack Chain

1. **Probe for Vulnerability**: Attacker sends HTTP GET requests containing common LFI payloads (e.g., `?file=../../../../etc/passwd` or `?page=php://filter/resource=index.php`) to web applications hosted on servers like Nginx, Apache, IIS, or Traefik.
2. **Information Disclosure**: A vulnerable web server or application processes the malicious input, leading to the display of local file contents (e.g., `/etc/passwd` for user accounts, `web.config` for application settings).
3. **Context Evasion**: Attacker attempts to retrieve `/proc/self/environ` to identify environment variables, secrets, and execution context on Linux systems.
4. **Credential Access**: Exposed configuration files (e.g., `wp-config.php`, `applicationhost.config`) are parsed for hardcoded database credentials, API keys, or other sensitive tokens.
5. **Persistence / Escalation**: Using the acquired information (e.g., writeable directories, credentials), the attacker may attempt to upload a webshell or modify existing scripts to achieve Remote Code Execution.
6. **System Compromise**: Successful RCE allows the attacker to fully control the underlying server, enabling data exfiltration, lateral movement, or further malicious activities.

## Impact

Successful LFI exploitation can lead to severe consequences, primarily sensitive data exposure. Attackers can gain access to user account details from `/etc/passwd`, administrative credentials from `wp-config.php` or `web.config`, and crucial system configuration from files like `applicationhost.config`. Disclosure of environment variables via `/proc/self/environ` can reveal API keys or other secrets. This information enables attackers to escalate privileges, install webshells, or perform remote code execution, ultimately compromising the entire web server and potentially leading to data exfiltration or complete system takeover. The scope of targeted systems includes widely used web servers such as Nginx, Apache, Apache Tomcat, IIS, and Traefik, making many organizations vulnerable.

## Recommendation

* Deploy the provided Sigma rule to your SIEM solution to detect LFI activity, specifically looking for HTTP GET requests targeting sensitive paths or using directory traversal.
* Configure web servers (Nginx, Apache, IIS, Traefik) to return `403` for requests resolving to sensitive directories like `/proc`, `/etc`, `/var/log`, `/inetpub`, or files such as `applicationhost.config` and `web.config`.
* Implement input validation and sanitization in web applications to prevent directory traversal (`..%2f`, `../`) and block protocol wrappers (`php://`, `data://`) from being interpreted as file paths.
* Rotate any exposed secrets (e.g., database credentials, API keys) identified in configuration files (e.g., `wp-config.php`, `web.config`) and invalidate active user sessions.
* Enable comprehensive web server access logging for Nginx, Apache, Apache Tomcat, IIS, and Traefik to capture `http.request.method`, `http.response.status_code`, and `url.original` for effective LFI detection.
