---
title: Detection of Remote WMI Command Execution via WMIC
slug: 2026-10-remote-wmi-command-attempt
description: Detection of WMIC.exe utilization with the node switch, a living-off-the-land technique used by threat actors for lateral movement and remote code execution.
date: "2026-10-12T17:56:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: The following analytic detects the execution of wmic.exe with the node switch, indicating an attempt to spawn a local or remote process.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: This activity is significant as it may indicate lateral movement or remote code execution attempts by an attacker.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/remote_wmi_command_attempt.yml
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
  - https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
rules:
  - title: Detect Remote WMI Command Attempt via WMIC
    description: Detects the execution of wmic.exe using the node switch, which is a common technique for remote process management or lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for WMIC node usage
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic guidance for T1047.
  hunt_leads:
    - lead: Historical search for wmic.exe /node commands
      technique_id: T1047
      data_needed:
        - Process command line logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source analytic logic.
  mitigation_plan:
    - priority: medium_term
      action: Restrict remote WMI access via Group Policy to authorized management stations
      owner: IT Operations
      addresses: T1047
      evidence: Standard security hardening practice.
---

Threat actors frequently use Windows Management Instrumentation (WMI) to perform lateral movement and execute code on remote systems. The `wmic.exe` utility remains a common choice for these activities due to its availability as a built-in Windows binary. By leveraging the `/node` switch, an attacker can specify a remote target system to execute processes, gather system information, or interact with WMI objects. This technique is often categorized as living-off-the-land, as it repurposes legitimate administrative functionality for malicious objectives. Observed in campaigns ranging from IcedID distribution to Volt Typhoon infrastructure compromises, this behavior is a high-fidelity indicator of potential unauthorized remote system access or persistent lateral movement attempts. Defenders should prioritize monitoring process creation events that involve `wmic.exe` with command-line arguments specifying a target node.

## Impact

Successful exploitation of WMI for remote execution can result in full system compromise, the deployment of ransomware or modular malware, and the facilitation of further reconnaissance within the environment. This technique has been documented in global attacks against critical infrastructure and enterprise networks, often acting as a bridge for privilege escalation and data exfiltration.

## Recommendation

* Enable Sysmon Event ID 1 or Windows Security Event ID 4688 to capture comprehensive process creation telemetry, including command-line arguments.
* Deploy the provided Sigma rule to your SIEM to monitor for `wmic.exe` executions featuring the `/node` switch.
* Review administrative usage patterns for WMI, as this activity is frequently performed by legitimate system management tools; baseline these expected behaviors to reduce false positives during investigations.
