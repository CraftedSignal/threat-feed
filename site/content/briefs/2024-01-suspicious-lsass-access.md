---
title: Suspicious LSASS Process Access
slug: 2024-01-suspicious-lsass-access
description: This rule identifies suspicious access attempts to the LSASS process, potentially indicating credential dumping attempts by filtering out legitimate processes and access patterns to focus on anomalies.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - lsass
  - windows
vendors:
  - Microsoft
  - Cisco
  - Oracle
products:
  - Windows Defender
  - Cisco AnyConnect Secure Mobility Client
  - Cisco Secure Client
  - Oracle Database
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md
rules:
  - title: Suspicious LSASS Access via Non-Whitelisted Process
    description: Detects access to LSASS process from processes not in the whitelist, potentially indicating credential dumping attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: LSASS Access with Unusual GrantedAccess Rights
    description: Detects access to LSASS process with GrantedAccess rights not typically associated with legitimate access, potentially indicating credential dumping.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: LSASS Access by Oracle SQL Loader
    description: Detects access to LSASS process by Oracle SQL Loader, which is unusual and potentially malicious.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The Local Security Authority Subsystem Service (LSASS) is a critical Windows component responsible for enforcing security policies and handling user authentication. Attackers often target LSASS to extract credentials, enabling unauthorized access and privilege escalation. This detection rule identifies suspicious access attempts to LSASS memory, which may indicate credential dumping activities. It filters out common legitimate processes and access patterns to highlight anomalous behaviors associated with credential theft. The rule is designed to detect unauthorized access attempts by monitoring process access events and filtering out known benign processes that interact with LSASS. It helps defenders identify potential credential access attempts before they lead to significant compromise.

## Attack Chain

1. An attacker gains initial access to a system, possibly through phishing or exploitation of a vulnerability.
2. The attacker executes a malicious process or script on the compromised system.
3. The malicious process attempts to gain a handle to the LSASS process.
4. The attacker's tool requests specific access rights to LSASS, such as `ReadProcessMemory` (0x0010) or `PROCESS_QUERY_INFORMATION` (0x0400), which are necessary for memory dumping.
5. The attacker's process bypasses or disables endpoint detection and response (EDR) solutions to avoid detection.
6. The tool dumps the LSASS memory, extracting sensitive information like usernames, passwords, and Kerberos tickets.
7. The attacker uses the extracted credentials to move laterally within the network, accessing other systems and resources.
8. The attacker achieves their objective, such as data exfiltration or deployment of ransomware.

## Impact

A successful LSASS memory dump can lead to the compromise of domain credentials, allowing attackers to move laterally within the network and gain access to sensitive data and systems. This can result in data breaches, financial loss, and reputational damage. Organizations across all sectors are vulnerable, particularly those with weak credential management practices. A single compromised account can lead to widespread damage, potentially affecting thousands of systems.

## Recommendation

*   Enable Sysmon process access event logging (Event ID 10) as described in the setup instructions linked in the rule to collect the necessary data.
*   Deploy the Sigma rule "Suspicious Lsass Process Access" to your SIEM and tune the exclusions based on your environment to reduce false positives.
*   Review and harden privileged account management practices to limit the impact of credential compromise.
*   Monitor systems for unusual process creation events, especially those spawning from unexpected locations, to identify potential initial access points.
*   Regularly scan systems for vulnerabilities and apply patches to prevent exploitation.
