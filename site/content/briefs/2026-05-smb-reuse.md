---
title: 'CVE-2026-5773: SMB Connection Reuse Vulnerability'
slug: 2026-05-smb-reuse
description: Microsoft published information about CVE-2026-5773, a vulnerability related to the incorrect reuse of SMB connections.
date: "2026-05-19T07:13:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*
tags:
  - smb
  - vulnerability
  - cve-2026-5773
vendors:
  - Microsoft
cves:
  - id: CVE-2026-5773
    cvss: 7.5
    epss: 0.00029
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5773
rules:
  - title: Detect CVE-2026-5773 Potential Exploitation - Multiple SMB Sessions from Same Source
    description: Detects CVE-2026-5773 exploitation attempt by monitoring multiple SMB sessions originating from the same source IP within a short timeframe, which may indicate connection reuse abuse.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-5773 Potential Exploitation - Unusual SMB Client
    description: Detects CVE-2026-5773 exploitation by looking for unusual SMB clients (User-Agent) in network traffic. This may indicate an attacker attempting to reuse or manipulate SMB connections.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On May 19, 2026, Microsoft disclosed CVE-2026-5773, a security vulnerability concerning the improper reuse of Server Message Block (SMB) connections. This flaw could potentially allow an attacker to intercept or manipulate SMB communications. While the specifics of the vulnerability are not detailed in the initial advisory, the incorrect handling of SMB sessions can lead to various security issues. It is crucial to apply the security updates provided by Microsoft to mitigate the risk associated with this vulnerability. Further investigation and patching are necessary to fully understand and address the potential impact.

## Attack Chain

1. An attacker identifies a vulnerable system utilizing SMB.
2. The attacker initiates an SMB connection to the target.
3. The vulnerable system incorrectly reuses an existing SMB connection for a different or unauthorized purpose (CVE-2026-5773).
4. The attacker intercepts the SMB traffic due to the incorrect session reuse.
5. The attacker gains unauthorized access to sensitive data transmitted over the SMB connection.
6. The attacker modifies SMB traffic, potentially executing arbitrary commands on the target system.
7. The attacker escalates privileges by leveraging the manipulated SMB connection.
8. The attacker achieves complete control over the compromised system, potentially leading to data exfiltration or system disruption.

## Impact

Successful exploitation of CVE-2026-5773 could allow an attacker to intercept or manipulate SMB communications, potentially leading to unauthorized access to sensitive data, privilege escalation, and complete system compromise. While the number of potential victims and affected sectors is unknown at this time, organizations relying on SMB for file sharing and inter-process communication are at risk.

## Recommendation

*   Apply the security updates released by Microsoft to patch CVE-2026-5773 on all affected systems.
*   Monitor SMB traffic for suspicious activity, such as unexpected connection reuse using the provided Sigma rules.
*   Review and enforce strict SMB security policies, including strong authentication and access controls.
