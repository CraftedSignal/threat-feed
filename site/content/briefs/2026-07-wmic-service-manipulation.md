---
title: Detection of Service Manipulation via WMIC.exe
slug: 2026-07-wmic-service-manipulation
description: This brief describes the detection of adversaries leveraging the native Windows Management Instrumentation Command-line (WMIC.exe) utility to start or stop services on compromised Windows systems, a common technique for persistence, privilege escalation, or lateral movement.
date: "2026-07-03T14:56:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lolbin
  - windows
  - persistence
  - execution
  - lateral-movement
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: Detects usage of wmic to start or stop a service
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_service_manipulation.yml
  - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
rules:
  - title: Service Started/Stopped Via Wmic.EXE
    description: Detects usage of wmic to start or stop a service, often indicating post-compromise activity for persistence or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Adversaries frequently utilize Living-off-the-Land Binaries (LOLBINs) to execute malicious actions while blending in with legitimate system activity. WMIC.exe, a built-in Windows utility, is one such tool often abused for system administration tasks, including the manipulation of services. This brief focuses on detecting instances where attackers invoke `wmic.exe` with `service call startservice` or `stopservice` commands. Such activity typically occurs post-compromise, indicating that an attacker has gained a foothold and is attempting to establish persistence, elevate privileges, or facilitate lateral movement by disabling security services, enabling malicious services, or modifying system configurations. Detecting these specific command-line arguments is crucial for defenders to identify attacker activity that directly impacts system integrity and availability, often serving as an early indicator of more advanced stages of an attack chain leading to data exfiltration or ransomware deployment.

## Impact

Successful manipulation of services using `wmic.exe` can lead to various detrimental outcomes. Attackers might disable security software, ensuring their malicious tools run unimpeded. They could stop critical legitimate services, causing denial-of-service or system instability, and replace them with malicious counterparts to maintain persistence and execute commands with elevated privileges. Such actions can facilitate lateral movement within a network, lead to data exfiltration, or prepare the ground for ransomware deployment, significantly impacting business operations, data confidentiality, and system integrity. While specific victim counts are not tied to this generic technique, any organization running Windows systems is susceptible to this abuse.

## Recommendation

*   Deploy the "Service Started/Stopped Via Wmic.EXE" Sigma rule provided in this brief to your SIEM solution.
*   Ensure comprehensive `process_creation` logging is enabled on all Windows endpoints, ideally through Sysmon, to capture detailed command-line arguments and parent-child process relationships for `wmic.exe`.
*   Review and alert on any detected instances where `wmic.exe` is used to manipulate critical services (e.g., security agents, domain controller services, core infrastructure applications) as this may indicate active compromise.
