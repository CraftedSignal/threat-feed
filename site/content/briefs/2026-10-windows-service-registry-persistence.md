---
title: Windows Service Creation via Registry Persistence
slug: 2026-10-windows-service-registry-persistence
description: Detection of unauthorized Windows service configuration via modification of registry ImagePath values, a common technique for persistence, privilege escalation, and lateral movement by various threat actors.
date: "2026-10-12T18:21:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - lateral-movement
  - registry-abuse
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: This activity is significant because it indicates potential unauthorized changes to service configurations, a common persistence technique used by attackers.
    confidence_band: high
rules:
  - title: Detect Windows Service ImagePath Registry Modification
    description: Detects the modification of registry keys defining Windows services via ImagePath, a common technique for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1574.011
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry monitoring rules for service path modifications
      owner: Detection Engineering
      due: 48h
      evidence: Analytic documented as a production-level detection by Splunk
  hunt_leads:
    - lead: Search for unauthorized modifications to service ImagePath values
      technique_id: T1574.011
      data_needed:
        - Sysmon Event ID 13
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Registry key modification is a primary indicator of this technique
  mitigation_plan:
    - priority: medium_term
      action: Restrict registry write access to SYSTEM\CurrentControlSet\Services
      owner: IT Operations
      addresses: T1574.011
      evidence: Limiting administrative registry access prevents arbitrary service modification
---

This detection identifies unauthorized modifications to Windows registry keys located within the 'SYSTEM\CurrentControlSet\Services' path, specifically targeting the 'ImagePath' value. By manipulating this registry entry, an attacker can define or modify the executable path for a service, forcing the system to run malicious payloads upon service start. This technique is a well-documented method for achieving persistence, escalating privileges, and facilitating lateral movement.

This activity is observed across numerous threat campaigns, including those attributed to the SolarWinds WHD RCE exploitation, the use of PlugX and Derusbi backdoors, and recent activity identified as Salt Typhoon. Defenders should monitor registry modifications involving the 'Services' registry hive as a high-fidelity indicator of potential system compromise and unauthorized configuration changes.

## Attack Chain

1. Attacker gains initial access to the target endpoint via exploitation or credential theft.
2. Attacker identifies a legitimate Windows service or creates a new service entry.
3. Attacker uses command-line tools like reg.exe or APIs to write a malicious path to the 'ImagePath' registry key.
4. The malicious binary is placed on the local disk or accessed via a remote share.
5. The Windows Service Control Manager (SCM) reads the modified 'ImagePath' upon service initiation or system reboot.
6. The SCM executes the malicious file with SYSTEM or high-privilege credentials.
7. The attacker establishes persistent execution and triggers further malicious activity such as lateral movement or data exfiltration.

## Impact

Successful abuse of service registry keys allows attackers to establish long-term persistence on a target host. This can lead to full system compromise, the execution of arbitrary code with SYSTEM privileges, and a foothold that facilitates lateral movement across the internal network. This technique has been linked to data theft, ransomware deployment, and long-term espionage activities.

## Recommendation

Prioritize monitoring for registry modifications that target the 'SYSTEM\CurrentControlSet\Services' key, specifically those involving the 'ImagePath' value name.

- Deploy the provided Sigma rule to your SIEM to monitor for Registry Event ID 13 (Sysmon) or equivalent registry modification logs.
- Baseline legitimate software installers and system updates that create or modify services to reduce false positives.
- Investigate any modifications to the 'Services' registry key occurring from non-standard processes, especially those originating from user-space applications or web servers.
