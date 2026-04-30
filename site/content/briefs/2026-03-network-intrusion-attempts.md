---
title: Multiple Network Intrusion Attempts Detected
slug: 2026-03-network-intrusion-attempts
description: Multiple network-based intrusion attempts were detected on 2026-03-14, targeting PHP information exposure, Fortigate VPN exploitation, sensitive file access, and credential exposure.
date: "2026-03-14T23:06:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - network-intrusion
  - vulnerability-exploitation
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://www.circl.lu/doc/misp/feed-osint/14501f7e-9084-4cba-8229-66baead78066.json
iocs:
  - type: ip
    value: 20.253.167.56
  - type: ip
    value: 2001:470:1:332::4
  - type: ip
    value: 2a09:bac1:36c0::2a6:14
  - type: ip
    value: 45.135.193.11
  - type: ip
    value: 2a09:bac1:36c0:1b0::2a8:46
  - type: ip
    value: 67.203.32.183
  - type: ip
    value: 158.115.252.4
  - type: ip
    value: 49.51.132.100
ioc_counts:
  ip: 8
rules:
  - title: Detect Fortigate CVE-2023-27997 Exploitation Attempts
    description: Detects repeated GET requests to /remote/logincheck, indicative of CVE-2023-27997 exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
  - title: Detect Requests to Hidden Environment Files
    description: Detects HTTP requests to common hidden environment file locations.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - network_connection
      - zeek
  - title: Detect Suspicious User Agent _TEST_
    description: Detects HTTP requests with the User-Agent string '_TEST_'.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - network_connection
      - zeek
rules_count: 3
---

On 2026-03-14, network intrusion detection systems (IDS) identified multiple suspicious activities originating from various IP addresses. These activities included attempts to access PHP information pages, exploit the Fortigate VPN vulnerability CVE-2023-27997, request hidden environment files, probe for SFTP/FTP password exposure, request Visual Studio Code sftp configuration files, and use a suspicious user agent string. While the specific actor remains unknown, the breadth of probes suggests a broad scanning approach, potentially preceding more targeted attacks. The activity is concerning due to the potential for information disclosure, unauthorized access, and credential compromise. Defenders should investigate the affected systems for signs of further compromise and implement appropriate mitigations.

## Attack Chain

1. **Initial Probing (Discovery):** The attacker scans the network, sending HTTP GET requests to common web server locations to identify potentially vulnerable systems. For example, the attacker probes for phpinfo pages.
2. **Targeted Vulnerability Scan:** After identifying potential targets, the attacker attempts to exploit specific vulnerabilities, such as CVE-2023-27997 on Fortigate VPN servers, by sending repeated GET requests to `/remote/logincheck`.
3. **Sensitive File Discovery:** The attacker probes for sensitive files by sending HTTP GET requests to discover hidden environment files (e.g., `.env`) using various techniques.
4. **SFTP/FTP Credential Exposure:** The attacker attempts to discover SFTP/FTP password exposure by scanning for `sftp-config.json` files.
5. **Information Leakage Attempts:** The attacker sends HTTP GET requests specifically targeting the `sftp.json` file used by Visual Studio Code, potentially revealing sensitive configuration information.
6. **User Agent Obfuscation:** The attacker uses a suspicious User-Agent string `_TEST_` to potentially mask their activity or test for detection capabilities.
7. **Possible Further Exploitation:** If any of the above steps are successful, the attacker might attempt to gain unauthorized access, escalate privileges, or exfiltrate sensitive data, depending on the specific vulnerability or information obtained.

## Impact

The observed activity poses a significant risk. Successful exploitation of CVE-2023-27997 could allow unauthorized VPN access. Exposure of environment files could reveal sensitive credentials and configuration details, potentially leading to account takeovers and data breaches. Discovery of SFTP/FTP credentials stored in `sftp-config.json` would enable unauthorized file access and modification. The overall impact could range from data leakage to complete system compromise, depending on the attacker's objectives and the success of their initial probing attempts.

## Recommendation

*   Deploy the Sigma rule `Detect Fortigate CVE-2023-27997 Exploitation Attempts` to identify and alert on exploitation attempts targeting this specific vulnerability (Sigma rule).
*   Block the IP addresses listed in the IOC table at the network perimeter to prevent further reconnaissance and exploitation attempts (IOC table).
*   Deploy the Sigma rule `Detect Requests to Hidden Environment Files` to identify attempts to access sensitive configuration files (Sigma rule).
*   Monitor network traffic for suspicious User-Agent strings, particularly those containing "_TEST_" to detect potentially malicious activity (IOC table).
*   Investigate any systems that have received requests for `phpinfo` pages, `sftp-config.json`, or hidden environment files for signs of compromise.
