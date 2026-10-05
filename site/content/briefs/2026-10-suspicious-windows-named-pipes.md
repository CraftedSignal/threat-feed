---
title: Detection of Malicious Windows Named Pipe Usage
slug: 2026-10-suspicious-windows-named-pipes
description: This analytic identifies the use of suspicious named pipes on Windows systems, a technique commonly leveraged by malware and post-exploitation frameworks for inter-process communication.
date: "2026-10-05T12:28:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - ipc
  - post-exploitation
  - named-pipe
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1055
    technique_name: Process Injection
    evidence: The rule leverages Sysmon EventCodes to identify pipe names often associated with injection or C2 activity.
    confidence_band: high
rules:
  - title: Detect Suspicious Windows Named Pipe Creation or Connection
    description: Detects creation or connection to known suspicious named pipes associated with post-exploitation tools, using Sysmon EventIDs 17 and 18.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1055
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
    - action: Deploy Sigma detection for EventID 17 and 18
      owner: Detection Engineering
      due: 48h
      evidence: Source provides Sysmon-based detection logic
  hunt_leads:
    - lead: Identify all non-signed binaries creating named pipes
      technique_id: T1055
      data_needed:
        - Sysmon EventID 17
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Named pipes are a primary IPC channel for unauthorized code
---

Security teams must monitor for the creation or connection to known suspicious named pipes to detect malicious inter-process communication (IPC). Attackers frequently use named pipes as a stealthy mechanism for data exfiltration, command-and-control (C2) communication, lateral movement, and privilege escalation. This technique is a hallmark of sophisticated post-exploitation toolkits such as Cobalt Strike, Brute Ratel, and various ransomware variants including LockBit and BlackByte. 

By leveraging Sysmon EventIDs 17 (Pipe Created) and 18 (Pipe Connected), defenders can gain visibility into how processes interact at the kernel level. This activity is often indicative of process injection or C2 beaconing. The detection of these indicators allows responders to identify potential compromises early in the kill chain, specifically during the execution or persistence phases, before further damage or exfiltration occurs.

## Impact

Successful abuse of named pipes facilitates the execution of malicious payloads, persistence mechanisms, and lateral movement within an enterprise environment. Observed threats using these techniques include ransomware operations, infostealers, and remote access trojans (RATs). If left undetected, these IPC channels allow attackers to maintain covert control over compromised hosts, potentially leading to mass data encryption, widespread system compromise, and significant operational disruption.

## Recommendation

Deploy the provided Sigma detection rule to monitor for unauthorized named pipe creation or connection events. Ensure Sysmon version 6.0.4 or higher is deployed across all Windows endpoints with logging enabled for EventIDs 17 and 18. Integrate this detection into a SIEM-based workflow to prioritize alerts involving high-risk processes that are not included in the established allowlist.

* Enable Sysmon EventID 17 and 18 telemetry.
* Deploy the provided Sigma rule to detect suspicious pipe activity.
* Configure automated drilldown searches for alerted endpoints to analyze process lineage.
