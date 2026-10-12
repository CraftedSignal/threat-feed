---
title: Windows Parent PID Spoofing via Explorer
slug: 2026-10-windows-explorer-spoofing
description: Malware utilizes parent process spoofing by spawning an instance of explorer.exe with the /root command-line argument to evade security monitoring and obscure process lineage.
date: "2026-10-12T18:17:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - privilege-escalation
  - windows
  - process-spoofing
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: The presence of /root in explorer.exe is significant as it may indicate parent process spoofing, a technique used by malware to evade detection.
    confidence_band: high
references:
  - https://x.com/CyberRaiju/status/1273597319322058752?s=20
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1134.004/T1134.004.yaml#L90
rules:
  - title: Detect Explorer Parent PID Spoofing Attempt
    description: Detects the execution of explorer.exe with the /root command-line parameter, which is a known indicator of parent PID spoofing for defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1134.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the Sigma rule to the SIEM and enable alerting for process creation events involving explorer.exe.
      owner: Detection Engineering
      due: 24h
      evidence: Analytic requirement to identify T1134.004 activity.
  hunt_leads:
    - lead: Search for instances of explorer.exe in process logs where the command line contains '/root'.
      technique_id: T1134.004
      data_needed:
        - Process creation events (Sysmon ID 1 / Security 4688)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic confirms this is a high-fidelity indicator.
---

This threat involves the manipulation of Windows process attributes, specifically the use of parent process spoofing to hide malicious activity. Threat actors execute explorer.exe with the /root command-line parameter, a technique that leverages the way Windows handles explorer shell integration to deceive security tools regarding the actual parentage of a process. By mimicking legitimate explorer.exe behavior or forcing the system to interpret the process under a different parent PID, adversaries aim to evade EDR and behavioral monitoring systems. This technique is typically employed to facilitate defense evasion, maintain persistence, or hide malicious sub-processes that would otherwise appear suspicious under a different, non-standard parent. Defenders should monitor for command-line arguments that deviate from standard operating system behavior for this core binary.

## Attack Chain

1. An initial malicious executable or script is executed on the compromised Windows host.
2. The adversary identifies a target process PID to use as the spoofed parent.
3. The malware executes the Windows API or a wrapper to create a process with the EXTENDED_STARTUPINFO_PRESENT flag.
4. The parent process attribute (AttributeParentProcess) is set to the target PID, often explorer.exe or another system process.
5. The malware executes the command: explorer.exe /root,[additional parameters].
6. The system spawns the new explorer.exe process, which inherits the spoofed parentage information.
7. The adversary uses the spoofed process as a container to inject further malicious code or execute secondary payloads.
8. Final objective achieved: concealment of malicious activity, persistence, or elevation of privilege within the environment.

## Impact

Successful execution of this technique allows an attacker to operate with a obscured execution context, significantly reducing the probability of detection by standard security tools that rely on accurate process lineage. This can lead to unauthorized data access, the deployment of further ransomware or infostealer payloads, and long-term undetected persistence within the compromised Windows environment.

## Recommendation

* Deploy the provided Sigma rule to detect the execution of explorer.exe with the anomalous /root command-line parameter.
* Ensure that process creation logging, specifically Sysmon Event ID 1 or Windows Security Event ID 4688, is enabled and capturing the full command-line strings for all processes.
* Use the Splunk CIM to normalize process data to ensure detection rules remain consistent across diverse endpoint telemetry.
* Audit endpoints for processes where the reported parent PID does not align with established process tree expectations for explorer.exe instances.
