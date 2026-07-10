---
title: Tenda CH22 Path Traversal Vulnerability (CVE-2026-5962)
slug: 2024-01-23-tenda-path-traversal
description: A path traversal vulnerability exists in Tenda CH22 version 1.0.0.6(468), affecting the R7WebsSecurityHandler function within the httpd component, allowing remote attackers to access sensitive files.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-5962
  - path-traversal
  - tenda
  - router
vendors:
  - Tenda
products:
  - CH22
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5962
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5962
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_55/README.md
  - https://vuldb.com/vuln/356515
rules:
  - title: Detect Path Traversal Attempts in Tenda CH22 via Web Logs
    description: Detects potential path traversal attempts targeting Tenda CH22 routers by monitoring web server logs for suspicious URL patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Path Traversal in HTTP Request Headers
    description: Detects path traversal attempts in HTTP request headers, potentially indicating exploitation of vulnerabilities like CVE-2026-5962.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5962 describes a path traversal vulnerability in Tenda CH22 router firmware version 1.0.0.6(468). The vulnerability resides within the `R7WebsSecurityHandler` function of the `httpd` component. This allows an unauthenticated, remote attacker to potentially read sensitive files on the device by manipulating the file paths in HTTP requests. The vulnerability was reported in April 2026, and public exploits are available, increasing the risk of exploitation. Routers are often exposed directly to the internet, making them prime targets for attackers looking to gain unauthorized access to internal networks or sensitive data.

## Attack Chain

1.  The attacker identifies a Tenda CH22 router running firmware version 1.0.0.6(468) accessible over the network.
2.  The attacker crafts a malicious HTTP GET or POST request targeting the `httpd` service.
3.  The request includes a manipulated URL containing path traversal sequences (e.g., `../`) within a filename parameter.
4.  The `R7WebsSecurityHandler` function fails to properly sanitize the supplied path.
5.  The `httpd` service processes the request and attempts to access the file specified by the attacker-controlled path.
6.  Due to the path traversal vulnerability, the service accesses files outside the intended web directory.
7.  The contents of the accessed file are returned in the HTTP response to the attacker.
8.  The attacker obtains sensitive information, such as configuration files, credentials, or other system data.

## Impact

Successful exploitation of this path traversal vulnerability allows an attacker to read arbitrary files on the Tenda CH22 router. This can lead to the disclosure of sensitive information such as router configuration details, Wi-Fi passwords, or credentials for other services. This information can be used for further attacks, such as gaining unauthorized access to the network behind the router, or using the router as a foothold for lateral movement. The number of affected devices and users is currently unknown.

## Recommendation

*   Monitor web server logs for suspicious URL requests containing path traversal sequences like `../` targeting Tenda CH22 devices based on the `webserver` category rule provided below.
*   Implement a web application firewall (WAF) rule to block requests containing path traversal attempts to mitigate the vulnerability as it exploits the `httpd` component.
*   Apply any available patches or firmware updates from Tenda to address CVE-2026-5962, if available.
