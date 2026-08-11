---
title: Sandworm-Linked UAC-0145 Targets IT Professionals via Fake Recruitment and Backdoored VPN
slug: 2026-08-sandworm-uac0145-vpn
description: The threat actor UAC-0145 (Sandworm) is targeting IT professionals with a recruitment-themed social engineering campaign that directs victims to install a malicious, backdoored WireGuard VPN client capable of arbitrary command execution.
date: "2026-08-11T19:45:54Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UAC-0145
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.002
    technique_name: Spearphishing Link
    evidence: attackers contact a potential victim - typically a system administrator or IT specialist - on behalf of an IT company
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: The PowerShell code decrypted in this way is then passed to the standard 'runScriptCommand' mechanism
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Scheduled Task
    evidence: The Windows VPN client also makes use of a PowerShell command to create a scheduled task
    confidence_band: high
iocs:
  - type: domain
    value: soprasteria-bg.com
ioc_counts:
  domain: 1
rules:
  - title: Detect Suspicious PowerShell Execution via WireGuard VPN Client
    description: Detects potentially malicious PowerShell commands executed by a VPN client process, indicative of CVE-like abuse or backdoored VPN software.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Since May 2026, the threat actor UAC-0145, a subgroup of the GRU-affiliated Sandworm (APT44), has engaged in a sophisticated social engineering campaign targeting IT administrators and system engineers. The attackers impersonate recruiters from legitimate organizations, such as Sopra Steria, using job portals and encrypted messaging apps like Telegram to build trust. Victims are eventually invited to a fake technical interview hosted on Zoom, where they are instructed to configure a 'corporate' VPN for a required assessment.

The core of the attack involves a modified WireGuard VPN client ('SopraVPN') hosted on SourceForge. The client has been instrumented with a custom 'SymmetricKey' configuration option that, when processed, executes BASE64-encoded PowerShell commands via the WireGuard 'PostUp' mechanism. This allows the threat actor to achieve unauthenticated remote code execution on the victim's host. Secondary payloads are subsequently retrieved via scheduled tasks on Windows or cURL on Linux, facilitating further stages of the compromise.

## Attack Chain

1. Attacker contacts the victim via job portals or messaging apps, masquerading as a recruiter to initiate a recruitment workflow.
2. Victim participates in a fake technical interview conducted over Zoom, often involving a perceived AI-generated persona.
3. Victim is directed to download a custom 'SopraVPN' client from SourceForge, branded as a legitimate corporate tool.
4. Victim imports the provided malicious configuration file containing the non-standard 'SymmetricKey' parameter into the VPN client.
5. The VPN client's modified configuration processor decodes the 'SymmetricKey' value into an AES-256-GCM key and payload.
6. The client executes the decrypted PowerShell code through the internal 'PostUp' command execution mechanism.
7. The PowerShell payload establishes persistence on the victim host, typically through the creation of a Windows Scheduled Task.
8. The malware downloads secondary payloads from attacker-controlled infrastructure via cURL (Linux) or PowerShell (Windows) to achieve the final objective.

## Impact

The campaign targets specialized IT personnel, granting the adversary direct command execution on high-privilege administrative endpoints. Successful exploitation allows for credential theft, lateral movement, and potential long-term persistence within target organizations. The use of fake recruiter personas and specific technical vetting processes increases the likelihood of high-value systems being compromised.

## Recommendation

* Deploy endpoint detection and response (EDR) rules to monitor for the execution of PowerShell commands spawned by processes masquerading as WireGuard (e.g., SopraVPN.exe).
* Block the known malicious domains and SourceForge project links associated with this campaign at the enterprise proxy and DNS resolver levels.
* Implement strict application control policies to prevent the execution of unauthorized or unverified VPN binaries in corporate environments.
* Audit scheduled task creation events for commands that involve PowerShell, especially those originating from non-standard or user-installed network utilities.
