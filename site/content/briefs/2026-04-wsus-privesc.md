---
title: Windows Server Update Service (WSUS) Privilege Escalation via CVE-2026-26174
slug: 2026-04-wsus-privesc
description: CVE-2026-26174 is a race condition vulnerability in Windows Server Update Service that allows an authorized attacker to elevate privileges locally.
date: "2026-04-14T18:23:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-26174
  - privilege-escalation
  - windows
  - wsus
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26174
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26174
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26174
iocs:
  - type: email
    value: '[email&#160;protected]'
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 2
rules:
  - title: Detect Suspicious WSUS Child Processes
    description: Detects unusual child processes spawned by the WSUS process (w3wp.exe), which could indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect WSUS File Modifications
    description: Detects modifications to files within the WSUS installation directory, which could indicate an attempted exploit.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-26174 describes a race condition vulnerability within the Windows Server Update Service (WSUS). Disclosed on April 14, 2026, this flaw allows a locally authenticated attacker with limited privileges to elevate their privileges to SYSTEM. The vulnerability stems from improper synchronization when WSUS handles concurrent requests, leading to a race condition that can be exploited to overwrite critical system files or manipulate system processes. Successful exploitation could grant an attacker full control over the affected system, potentially enabling lateral movement within the network, data exfiltration, or deployment of malware. Due to the critical role of WSUS in managing updates across an enterprise, this vulnerability poses a significant risk to organizations relying on WSUS for patch management.

## Attack Chain

1.  Attacker authenticates to the target Windows system with a low-privileged account.
2.  The attacker crafts a malicious request designed to trigger the race condition in WSUS. This might involve sending multiple, simultaneous update requests.
3.  WSUS processes the crafted requests concurrently, leading to unsynchronized access to shared resources.
4.  Due to the race condition, the attacker gains the ability to manipulate a shared resource, such as a temporary file or a registry key, used by WSUS.
5.  The attacker exploits the manipulated shared resource to overwrite a critical system file within the WSUS directory (e.g., a DLL loaded by the WSUS service) or modify a registry setting used by WSUS for configuration.
6.  WSUS service restarts or reloads the modified component, executing the attacker's injected code with elevated privileges.
7.  The attacker's code executes with SYSTEM privileges, granting them full control over the system.
8.  The attacker leverages the elevated privileges to install malicious software, create new accounts, or perform other unauthorized actions.

## Impact

Successful exploitation of CVE-2026-26174 allows a local attacker to elevate privileges to SYSTEM. This level of access grants complete control over the compromised machine. In a networked environment, this could lead to lateral movement to other systems, exfiltration of sensitive data, or the deployment of ransomware. Given that WSUS is often deployed across numerous systems, a single successful exploit could compromise a large number of machines. The vulnerability has a CVSS v3.1 score of 7.0, indicating a high severity.

## Recommendation

*   Apply the patch released by Microsoft to address CVE-2026-26174 on all WSUS servers immediately.
*   Monitor process creation events for unusual processes spawned by the WSUS service (w3wp.exe) using the "Detect Suspicious WSUS Child Processes" Sigma rule to detect potential exploitation attempts.
*   Monitor file modifications within the WSUS installation directory (typically `C:\Program Files\Update Services\`) using the "Detect WSUS File Modifications" Sigma rule.
*   Review WSUS logs for any unusual activity or errors that might indicate an attempted exploitation of CVE-2026-26174.
