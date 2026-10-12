---
title: Detection of Local Administrator Account Creation via Net.exe
slug: 2026-10-net-admin-creation
description: This analytic identifies attackers attempting to establish persistence or escalate privileges by using net.exe to add users to local administrator groups.
date: "2026-10-12T18:03:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - windows
  - net-exe
  - local-admin
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: This activity is significant as it may indicate an attacker attempting to gain persistent access or escalate privileges.
    confidence_band: high
rules:
  - title: Detect Windows Local Administrator Account Creation via Net.exe
    description: Detects the creation of a new local administrator account using net.exe /add, a common technique for persistence or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1136.001
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
    - action: Deploy detection for net.exe usage with administrative keywords.
      owner: Detection Engineering
      due: 24h
      evidence: Analytic rule provided in this brief.
  hunt_leads:
    - lead: Identify all occurrences of net.exe /add in historical logs to baseline administrative behavior.
      technique_id: T1136.001
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Analytic designed to catch unauthorized persistence attempts.
---

This detection analytic identifies the creation of a local administrator account on Windows systems by monitoring the usage of 'net.exe' with the '/add' parameter in conjunction with administrator-related group names. This activity is a common indicator of attackers attempting to establish persistence or escalate privileges on a compromised host. Multiple threat actors and malware families, including Medusa Ransomware, Azorult, DarkGate, and Lapsus$ affiliates, utilize this technique to maintain access post-exploitation. Detection engineers should look for process execution patterns involving net.exe that match this command line syntax, while accounting for legitimate administrative tasks.

## Impact

Successful execution of this technique allows an adversary to maintain long-term access to a system, bypass security controls, and perform further lateral movement or data exfiltration. If confirmed malicious, this activity often represents a late stage in the kill chain where an attacker has already obtained high-privileged credentials or found a path to execute system commands.

## Recommendation

* Deploy the Sigma rule below to monitor for local group modification commands.
* Enable Sysmon Event ID 1 (Process Creation) and ensure command-line arguments are captured in logs.
* Use the Splunk Common Information Model (CIM) to map process execution data to the Endpoint data model.
* Prioritize alerts where the parent process is a non-standard utility or a web-server-related process, indicating potential remote code execution exploitation.
