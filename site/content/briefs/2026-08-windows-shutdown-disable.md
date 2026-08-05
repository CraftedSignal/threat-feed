---
title: Detection of Registry-Based Shutdown Button Disabling
slug: 2026-08-windows-shutdown-disable
description: This brief details a defense evasion technique involving registry modifications to disable the shutdown button on Windows systems, a tactic historically used by ransomware like KillDisk to hinder recovery and persistence removal.
date: "2026-08-05T21:12:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The following analytic detects suspicious registry modifications that disable the shutdown button on a user's logon screen.
    confidence_band: high
rules:
  - title: Detect Registry Modification to Disable Shutdown
    description: Detects modifications to Windows registry keys that disable the shutdown button, a technique used by ransomware to hinder recovery.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
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
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Required to monitor for T1112 activity.
  hunt_leads:
    - lead: Registry modifications to 'Policies\System' or 'Policies\Explorer'
      technique_id: T1112
      data_needed:
        - Sysmon Event ID 13 or EDR registry monitoring
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source analytic logic.
  mitigation_plan:
    - priority: short_term
      action: Review Group Policy objects for power management restrictions.
      owner: IT Operations
      addresses: T1112
      evidence: Source notes on false positives.
---

Malware, particularly destructive ransomware such as KillDisk, often attempts to manipulate Windows system policies to restrict user access to critical system functions. By modifying specific registry keys, an attacker can disable the shutdown option from the logon screen. This action is designed to hinder system usability, complicate recovery efforts by preventing a clean reboot, and make it more difficult for administrators to remove malicious modifications or restore the system state. Security operations teams should monitor registry modifications targeting these specific policy keys, as they are rarely modified during normal operations and often signal an attempt to maintain control over a compromised host or prevent incident responders from easily rebooting the system.

## Attack Chain

1. Attacker gains administrative access to the target endpoint through initial infection or privilege escalation.
2. Attacker identifies the target registry hive for system policies (HKLM or HKCU).
3. Attacker uses command-line tools (e.g., reg.exe) or native APIs to modify the registry.
4. Attacker targets 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\shutdownwithoutlogon' to set the value to 0x00000000.
5. Attacker targets 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoClose' to set the value to 0x00000001.
6. The system policy takes effect, removing the shutdown button from the Windows logon interface.
7. Final objective is achieved, impeding system recovery and hindering the incident response process.

## Impact

Successful execution of this technique prevents users and administrators from restarting the affected machine through standard interface methods. This significantly impacts incident response and recovery operations, as it complicates the ability to initiate a clean boot or boot into safe mode to remediate malicious changes, thereby extending the dwell time and impact of ransomware or wiper attacks.

## Recommendation

- Deploy the provided Sigma rule to monitor for registry modifications to shutdown policy keys across all endpoints.
- Enable Sysmon Event ID 13 (RegistryEvent) logging and ensure the Sysmon TA is configured to capture the full path and value data of registry modifications.
- Investigate any hits in the SIEM to differentiate between legitimate administrative hardening and unauthorized tampering by malicious processes.
- Use the drilldown searches provided to pivot into historical risk events for any affected host to determine if this activity is part of a broader compromise.
