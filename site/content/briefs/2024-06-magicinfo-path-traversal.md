---
title: Samsung MagicINFO 9 Server Path Traversal Vulnerability (CVE-2024-7399)
slug: 2024-06-magicinfo-path-traversal
description: A path traversal vulnerability in Samsung MagicINFO 9 Server could allow an attacker to write arbitrary files with system privileges, potentially leading to code execution or system compromise.
date: "2024-06-19T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - path-traversal
  - cve-2024-7399
  - samsung
vendors:
  - Samsung
products:
  - MagicINFO 9 Server
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: 'Server Software Component: Web Shell'
cves:
  - id: CVE-2024-7399
    cvss: 8.8
    epss: 0.82263
references:
  - https://www.cve.org/CVERecord?id=CVE-2024-7399
  - https://security.samsungtv.com/securityUpdates
  - https://nvd.nist.gov/vuln/detail/CVE-2024-7399
rules:
  - title: MagicINFO Path Traversal Attempt
    description: Detects potential path traversal attempts targeting Samsung MagicINFO Server in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Suspicious File Creation in Web Directories
    description: Detects the creation of suspicious files (e.g., webshells) in web server directories, potentially indicating exploitation of a vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical path traversal vulnerability, identified as CVE-2024-7399, affects Samsung MagicINFO 9 Server. This flaw could be exploited by an attacker to write arbitrary files to the server with system-level privileges. Successful exploitation could lead to a complete compromise of the MagicINFO server, potentially allowing attackers to execute arbitrary code, install backdoors, or manipulate data stored on the server. Given the potential for widespread impact, organizations utilizing MagicINFO 9 Server should prioritize patching or mitigating this vulnerability immediately. The vulnerability was added to the CISA Known Exploited Vulnerabilities (KEV) catalog, highlighting its active exploitation risk.

## Attack Chain

1.  The attacker identifies a vulnerable MagicINFO 9 Server instance exposed to the network.
2.  The attacker crafts a malicious HTTP request containing a path traversal sequence (e.g., "../") in a file upload or download parameter.
3.  The server improperly processes the path, failing to sanitize the input and allowing the attacker to traverse outside the intended directory.
4.  The attacker uses the path traversal vulnerability to write a malicious file (e.g., a web shell or executable) to a sensitive directory, such as the web server's root directory or a startup folder.
5.  The attacker executes the malicious file, gaining arbitrary code execution on the server with system privileges.
6.  The attacker establishes a persistent backdoor for future access, potentially installing tools for lateral movement and privilege escalation.
7.  The attacker leverages their system privileges to access sensitive data, modify system configurations, or launch further attacks against the internal network.

## Impact

Successful exploitation of CVE-2024-7399 can lead to complete system compromise, potentially affecting all connected displays and content managed by the MagicINFO server. This could result in unauthorized access to sensitive data, disruption of digital signage operations, and the potential for further attacks against the organization's internal network. The vulnerability has been added to the CISA KEV catalog, indicating active exploitation, and therefore a high risk of exploitation.

## Recommendation

*   Apply the mitigations provided by Samsung as described in their security update (https://security.samsungtv.com/securityUpdates).
*   If mitigations are unavailable, discontinue use of the product, as suggested by CISA.
*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., "../") targeting the MagicINFO server. Use the `MagicINFO Path Traversal Attempt` Sigma rule to detect such attempts in web server logs.
*   Implement strict input validation and sanitization for all file upload and download functionalities on the MagicINFO server.
*   Monitor for the creation of unexpected files in sensitive directories, such as web server root directories or system startup folders. Use the `Suspicious File Creation in Web Directories` Sigma rule to detect such activity.
