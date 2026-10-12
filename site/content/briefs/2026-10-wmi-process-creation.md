---
title: Detection of WMI Process Creation via Command Line
slug: 2026-10-wmi-process-creation
description: This brief documents the detection of WMI 'process call create' command-line patterns used by adversaries to execute arbitrary payloads and maintain persistence.
date: "2026-10-12T18:25:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - wmi
  - defense-evasion
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: Adversaries frequently leverage WMI as a living-off-the-land technique to execute malicious payloads, bypass security controls, and maintain persistence.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: This behavior could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: This behavior could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment.
    confidence_band: high
rules:
  - title: Detect Suspicious WMI Process Call Create
    description: Detects the use of wmic to spawn processes via the process call create method, which is commonly used by adversaries for execution.
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
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule for detecting wmic process call create.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided in source.
  hunt_leads:
    - lead: Search for historical execution of wmic process call create to identify past compromise.
      technique_id: T1047
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique commonly used by observed threat actors.
  mitigation_plan:
    - priority: short_term
      action: Restrict access to management tools like wmic where not required for administrative functions.
      owner: IT Operations
      addresses: T1047
      evidence: Standard hardening practice.
---

Adversaries frequently leverage Windows Management Instrumentation (WMI) as a living-off-the-land technique to execute malicious payloads, bypass traditional security controls, and facilitate lateral movement. This activity, tracked as T1047, often involves the use of the `wmic` utility to invoke the `process call create` method. This method allows an attacker to spawn processes on local or remote hosts using built-in system administration tools, which can often evade signature-based detection mechanisms. Defenders should prioritize visibility into command-line arguments that correlate with these specific WMI parameters. Threat actors, including groups associated with Volt Typhoon, Qakbot, and IcedID, have been observed utilizing WMI for malicious process execution during campaigns targeting critical infrastructure and enterprise environments.

## Attack Chain

1. Attacker gains initial access to a target system via phishing or exploitation of internet-facing services.
2. Attacker establishes a foothold on the compromised endpoint.
3. Attacker uses living-off-the-land binaries (LotLbins) to evade detection.
4. Attacker executes `wmic.exe` with `process call create` parameters to launch a malicious payload or script.
5. The WMI service spawns the requested process under the context of the service account.
6. The spawned process executes arbitrary commands, such as downloading additional malware, credential harvesting, or lateral movement.
7. Attacker achieves persistence or objective fulfillment while the malicious activity remains disguised as legitimate administrative traffic.

## Impact

Successful exploitation of WMI for process creation can result in unauthorized code execution, privilege escalation, and long-term persistence within an environment. Threat actors like Volt Typhoon and groups deploying ransomware (e.g., Cactus) have used these techniques to maintain access across critical infrastructure and enterprise networks. Unauthorized execution can lead to full system compromise, data exfiltration, and significant operational disruption.

## Recommendation

* Deploy detection logic to identify `wmic` command lines containing "process", "call", and "create" keywords.
* Enable Sysmon Event ID 1 (Process Creation) and Windows Security Event ID 4688 to capture full command-line strings for monitoring.
* Use the provided Sigma rule to detect suspicious WMI activity in SIEM environments.
* Baseline administrative activity involving WMI to reduce false positives generated by legitimate system maintenance tasks.
