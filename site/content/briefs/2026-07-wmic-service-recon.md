---
title: Service Reconnaissance Via Wmic.EXE
slug: 2026-07-wmic-service-recon
description: Adversaries leverage the native Windows Management Instrumentation Command-line (WMIC) utility to perform service reconnaissance on remote systems, querying for existing services as a prelude to identifying potential targets for lateral movement or privilege escalation.
date: "2026-07-03T14:52:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - reconnaissance
  - wmic
  - internal-recon
vendors:
  - Microsoft
products:
  - Windows Operating System
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: An adversary might use WMI to check if a certain remote service is running on a remote device.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_recon_service.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1047/T1047.md
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic
  - https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service
rules:
  - title: Service Reconnaissance Via Wmic.EXE
    description: Detects an adversary using WMIC to check for running services on local or remote devices, indicating reconnaissance activity. This rule filters out commands used for service manipulation (start/stop/change) to reduce false positives.
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

Adversaries frequently utilize built-in operating system tools to perform reconnaissance within a compromised environment, blending in with legitimate administrative activity. One such tool is `wmic.exe`, the Windows Management Instrumentation Command-line utility. Attackers specifically use `wmic.exe` to query service information on remote devices, often as an initial step to map network services, identify running applications, or detect potential vulnerabilities. This activity helps them understand the target's environment, aiding in decisions regarding lateral movement, privilege escalation, or further exploitation. The technique involves executing `wmic.exe` with specific commands targeting remote nodes and querying the "service" class, which can result in output indicating service availability or error messages if the host is unreachable or the service doesn't exist. This reconnaissance is a foundational step in many attack chains, allowing threat actors to gather crucial intelligence for subsequent stages.

## Attack Chain

This brief focuses on a specific reconnaissance technique rather than a complete, multi-stage attack chain. The observed behavior centers on the execution of a single command-line utility for information gathering:

1.  **Execution of WMIC for Service Query**: An attacker executes `wmic.exe` on a compromised host or directly from their attacking machine (if initial access is achieved through a different vector), targeting a remote system.
2.  **Remote System Identification**: The command includes `/node:` parameter specifying the remote IP address or hostname to query.
3.  **Service Class Query**: The `service` class is specified, indicating the attacker is interested in service-related information.
4.  **Information Request**: Additional parameters like `list brief` or `get Caption,Name,State` are used to retrieve specific service attributes.
5.  **Output Analysis**: The attacker parses the output, which lists running services, provides "No instance(s) Available" if a service is not found, or returns "The RPC server is unavailable" if the remote host is unreachable.
6.  **Intelligence Gathering**: The collected service information helps the attacker identify running software, potential attack surfaces, or indicators of security tooling, informing subsequent attack decisions such as lateral movement or privilege escalation.

## Impact

While service reconnaissance via WMIC itself does not directly result in immediate damage or data loss, its successful execution provides adversaries with critical intelligence about the network environment. This information enables them to identify high-value targets, vulnerable services, or unpatched systems, significantly increasing the likelihood of successful lateral movement, privilege escalation, and ultimately, data exfiltration or system compromise. Failure to detect and respond to such reconnaissance activities allows attackers to progress undetected through their kill chain, potentially leading to widespread network disruption, ransomware deployment, or sensitive data theft.

## Recommendation

*   Deploy the Sigma rule included in this brief to your SIEM and tune for your environment to detect `wmic.exe` service reconnaissance.
*   Enable Sysmon process-creation logging (Event ID 1) on all Windows endpoints and servers to ensure the necessary telemetry for the provided Sigma rule.
*   Review network firewall and host-based firewall logs for unusual outbound connections to identify remote WMIC queries.
