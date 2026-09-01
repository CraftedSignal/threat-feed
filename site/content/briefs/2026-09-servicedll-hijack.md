---
title: ServiceDLL Registry Hijack for Persistence
slug: 2026-09-servicedll-hijack
description: Adversaries manipulate the ServiceDLL registry value within Windows service configurations to achieve persistence by forcing the loading of unauthorized malicious dynamic link libraries.
date: "2026-09-01T12:07:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: This is often used as a method of persistence.
    confidence_band: high
rules:
  - title: Detect ServiceDLL Registry Value Modification
    description: Detects changes to the ServiceDLL value in the Windows registry, a common technique for service-based persistence
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.003
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
    - action: Deploy the Sigma rule for ServiceDLL hijacking
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in source
  hunt_leads:
    - lead: Search for non-standard ServiceDLL paths in registry
      technique_id: T1543.003
      data_needed:
        - Registry audit logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source documentation of ServiceDLL hijacking
---

The ServiceDLL registry key is a component of Windows service configuration that defines the path to the DLL file loaded by the service host process (svchost.exe) when a service starts. Threat actors exploit this mechanism by modifying the ServiceDLL registry entry to point to a malicious DLL they have placed on the system. When the service is triggered or the system reboots, the service host process inadvertently loads the attacker-supplied library. This technique allows for persistence and privilege escalation, as the malicious code runs within the context of the service, often with SYSTEM-level privileges. This behavior has been observed in various backdoors, including the TinyTurla malware, which leverages this method to maintain access to compromised environments. Defenders must monitor registry modifications in service parameters to identify anomalous paths or unapproved DLL associations.

## Attack Chain

1. Attacker gains initial access to the system through methods such as phishing or exploitation of internet-facing services.
2. Attacker performs privilege escalation to gain administrative or SYSTEM-level access necessary to modify system registry keys.
3. Attacker drops a malicious DLL file into a directory where the service host can execute it, often choosing locations that appear legitimate.
4. Attacker identifies a target service configuration key under HKLM\SYSTEM\CurrentControlSet\Services.
5. Attacker modifies the 'ServiceDll' registry value within the 'Parameters' subkey of the target service, pointing it to the malicious DLL.
6. Attacker restarts the targeted service or forces a system reboot to trigger the service host (svchost.exe) to load the specified DLL.
7. The malicious code executes within the service host process, establishing persistence and potentially performing further malicious activity.

## Impact

Successful exploitation allows for long-term persistence within an environment, enabling ongoing command and control, data exfiltration, and the ability to operate with elevated system privileges. This technique is often used to maintain access after initial entry is remediated, complicating incident response and recovery efforts.

## Recommendation

Detection engineering teams should monitor for unauthorized registry modifications targeting the 'ServiceDll' value.
* Deploy the provided Sigma rule to detect registry set operations on 'ServiceDll' keys.
* Enable Sysmon Event ID 13 (RegistryEvent) to capture modifications to HKLM\SYSTEM\CurrentControlSet\Services\*\Parameters\ServiceDll.
* Establish a baseline of legitimate ServiceDLL values and alert on modifications that point to non-standard or user-writable file paths.
