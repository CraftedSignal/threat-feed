---
brief_id: brief-2024-01-24-ntlm-relay-http
event_id: brief-2024-01-24-ntlm-relay-http
revision: 2
activity_at: "2024-01-24T12:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:4d3eafcdf3bf64f37ad612116c93ef6b490ac1a881e4c8672e9a614359911d9a
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Potential Local NTLM Relay via HTTP using Windows Printer Spooler
slug: 2024-01-24-ntlm-relay-http
description: This rule identifies attempts to coerce local NTLM authentication via HTTP using the Windows Printer Spooler service as a target, which adversaries may use to elevate privileges on a compromised system.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - ntlm-relay
  - credential-access
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1212
    technique_name: Exploitation for Credential Access
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://github.com/med0x2e/NTLMRelay2Self
  - https://github.com/topotam/PetitPotam
  - https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py
rules:
  - title: Detect Potential Local NTLM Relay via HTTP
    description: Detects suspicious rundll32.exe executions that load davclnt.dll and attempt to access named pipes via HTTP, indicating a potential NTLM relay attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1187
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential Local NTLM Relay via HTTP - Alternate Detection
    description: Detects suspicious rundll32.exe executions that load davclnt.dll and attempt to access named pipes via HTTP, indicating a potential NTLM relay attack. This rule uses an alternate detection method by focusing on process arguments.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1187
      - T1218.011
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies potential NTLM relay attacks targeting the Windows Printer Spooler service. Attackers exploit this service to coerce NTLM authentication over HTTP. The rule focuses on detecting suspicious rundll32.exe executions that invoke WebDAV client DLLs with specific arguments, which indicates attempts to access named pipes via HTTP. This technique can be combined with other methods to achieve privilege escalation on a compromised Windows system. The activity is detected through process monitoring and command-line analysis, specifically looking for rundll32 executing davclnt.dll with HTTP paths to named pipes. The references indicate that this behavior has been seen in conjunction with tools like PetitPotam and NTLMRelay2Self. This activity has been observed being used since at least 2022, and continues to be relevant for defenders as a post-exploitation technique.

## Attack Chain

1. An attacker gains initial access to a Windows system (e.g., via phishing or exploiting a public-facing application).
2. The attacker uses rundll32.exe to load the WebDAV client DLL (davclnt.dll) using the DavSetCookie function.
3. The command line includes an HTTP path targeting a named pipe associated with the Printer Spooler service (e.g., `/print/pipe/`, `/pipe/spoolss`, or `/pipe/srvsvc`).
4. This action coerces the system to authenticate to the attacker-controlled HTTP endpoint.
5. The attacker relays the captured NTLM authentication to another service or system.
6. If successful, the attacker gains unauthorized access to the targeted service or system.
7. The attacker leverages the gained access for further actions, such as lateral movement or data exfiltration.
8. The final objective is often to escalate privileges within the domain.

## Impact

Successful exploitation of this NTLM relay technique can lead to complete domain compromise. An attacker can gain control over critical systems, including domain controllers, leading to widespread data breaches, system downtime, and financial losses. The targets are typically organizations running vulnerable Windows systems and Active Directory environments. The number of victims could range from individual machines to entire networks.

## Recommendation

*   Deploy the Sigma rule `Detect Potential Local NTLM Relay via HTTP` to your SIEM to identify suspicious rundll32.exe executions.
*   Enable Sysmon process-creation logging to provide the data required to activate the Sigma rule.
*   Monitor network connections for unusual HTTP traffic originating from rundll32.exe to named pipes, as described in the Attack Chain.
*   Review the false positive analysis section in the content of this brief to create appropriate exclusions.
*   Consider blocking the execution of rundll32.exe with davclnt.dll and HTTP paths to named pipes in your environment, if such executions are not legitimate.
*   Implement network segmentation to limit the exposure of critical services and reduce the risk of similar attacks, as mentioned in the original analysis.
*   Audit and restrict the use of the Windows Printer Spooler service where possible to minimize the attack surface, considering the information in the Overview section.
