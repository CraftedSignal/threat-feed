---
title: CVE-2026-32156 Use-After-Free Vulnerability in Windows UPnP Device Host
slug: 2026-04-upnp-use-after-free
description: CVE-2026-32156 is a use-after-free vulnerability in the Windows Universal Plug and Play (UPnP) Device Host service that allows an unauthorized attacker to execute code locally.
date: "2026-04-14T18:39:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - use-after-free
  - windows
  - upnp
  - code-execution
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2026-32156
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32156
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32156
rules:
  - title: Detect UPnP Service Launching Suspicious Processes
    description: Detects suspicious child processes spawned by the UPnP Device Host service (upnphost.dll), which could indicate exploitation of CVE-2026-32156.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect UPnP Service Connecting to External IP
    description: Detects suspicious network connections initiated by the UPnP Device Host service to external IPs, which could indicate exploitation of CVE-2026-32156.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32156 is a use-after-free vulnerability affecting the Windows Universal Plug and Play (UPnP) Device Host service. This vulnerability allows a local, unauthorized attacker to execute arbitrary code. The vulnerability arises from improper memory management within the UPnP service when handling device discovery or control requests. Successful exploitation requires specific conditions to trigger the use-after-free condition. The vulnerability was reported to Microsoft and assigned a CVSS v3.1 base score of 7.4, indicating a high severity. Exploitation of this vulnerability leads to arbitrary code execution, potentially allowing the attacker to gain elevated privileges on the affected system. It's crucial for defenders to apply the patch released by Microsoft to mitigate the risk.

## Attack Chain

1. An attacker gains initial access to the target system through some other means (e.g., phishing, exploiting a different vulnerability, or physical access).
2. The attacker crafts a malicious UPnP device description or control message.
3. The attacker sends the crafted message to the Windows UPnP Device Host service (upnphost.dll).
4. The UPnP service parses the malicious message, triggering a use-after-free condition due to improper memory management.
5. The attacker leverages the use-after-free condition to overwrite memory, gaining control of the program execution flow.
6. The attacker injects and executes arbitrary code within the context of the UPnP Device Host service.
7. The attacker escalates privileges from the UPnP Device Host service (running as Local Service) to SYSTEM.
8. The attacker achieves arbitrary code execution with SYSTEM privileges, allowing them to install malware, modify system settings, or steal sensitive data.

## Impact

Successful exploitation of CVE-2026-32156 allows an attacker to execute arbitrary code with SYSTEM privileges on a vulnerable Windows system. This could allow the attacker to install malware, steal sensitive data, or take complete control of the affected system. The vulnerability is locally exploitable, meaning an attacker needs some form of access to the target machine to initiate the exploit. While no widespread exploitation has been reported, the potential impact of arbitrary code execution warrants immediate patching and monitoring.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-32156 on all affected Windows systems (reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32156).
*   Monitor process creation events for suspicious activity originating from the `upnphost.dll` or `svchost.exe` processes, which host the UPnP service. Use the Sigma rule provided to detect potential exploitation attempts.
*   Enable process auditing to capture detailed information about process creation and execution, which can aid in identifying exploitation attempts (reference: Sigma rule logsource).
