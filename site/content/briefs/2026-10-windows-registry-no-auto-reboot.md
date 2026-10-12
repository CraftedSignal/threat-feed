---
title: Detection of Registry Modification to Disable Automatic Windows Update Reboots
slug: 2026-10-windows-registry-no-auto-reboot
description: Adversaries, including RedLine Stealer operators, modify the 'NoAutoRebootWithLoggedOnUsers' registry value to prevent system reboots, facilitating persistence and uninterrupted malicious operations.
date: "2026-10-12T18:12:57Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - RedLine Stealer
tags:
  - defense-evasion
  - registry-modification
  - persistence
  - malware
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
    evidence: This detection leverages the Endpoint data model to identify changes to the registry path SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers with a value of 0x00000001.
    confidence_band: high
references:
  - https://learn.microsoft.com/de-de/security-updates/windowsupdateservices/18127499
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1112/T1112.yaml
rules:
  - title: Detect Windows Registry Modification to Disable Auto Reboot
    description: Detects modifications to the Windows Update registry key that prevent automatic reboots while a user is logged on, a technique used by malware for persistence.
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
    - action: Deploy Sigma rule to identify unauthorized registry modifications.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides analytic logic for this behavior.
  hunt_leads:
    - lead: Search for existing registry modifications of 'NoAutoRebootWithLoggedOnUsers' across the estate.
      technique_id: T1112
      data_needed:
        - Registry modification logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Identify potential persistent threats currently active.
  mitigation_plan:
    - priority: medium
      action: Enforce GPO policies to override manual registry changes to Windows Update settings.
      owner: IT Operations
      addresses: Persistence via registry modification
      evidence: Registry changes to policies can be centrally managed via Group Policy.
---

Adversaries and malware, such as the RedLine Stealer infostealer, frequently employ defense evasion techniques to maintain long-term access to compromised hosts. A documented tactic involves modifying the Windows registry key `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers` to a value of `0x00000001`. 

By setting this value, the attacker prevents the operating system from performing automatic reboots following Windows Update installations while a user session is active. This ensures that the attacker's malicious payloads, C2 persistence mechanisms, or data exfiltration processes are not disrupted by unplanned system restarts. While this configuration is occasionally used by system administrators for uptime-critical environments, its sudden appearance in a host's registry - particularly when performed by non-standard processes - is a high-fidelity indicator of post-exploitation persistence hardening.

## Attack Chain

1. Initial infection via malware such as RedLine Stealer.
2. Execution of a dropper or secondary payload with local administrative privileges.
3. Escalation of privileges to modify system-level registry keys.
4. Accessing the registry hive at `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\`.
5. Setting the `NoAutoRebootWithLoggedOnUsers` value to `0x00000001`.
6. Persistence maintained through ongoing malicious operations without interruption.
7. Deployment of subsequent payloads or exfiltration of sensitive data.
8. Final objective reached: long-term persistence on the compromised endpoint.

## Impact

Successful exploitation of this technique allows an attacker to harden their foothold on the target machine. By disabling automatic reboots, the attacker ensures that security updates do not inadvertently terminate their process or require a reboot that might alert the user or interfere with exfiltration. This tactic has been observed in campaigns targeting Windows endpoints across various sectors, impacting the integrity and stability of the host environment.

## Recommendation

Prioritize monitoring for unauthorized registry modifications targeting Windows Update policies to detect early-stage persistence hardening.

* Deploy the provided Sigma rule to your SIEM to flag suspicious registry changes.
* Audit endpoint telemetry using Sysmon Event ID 13 to identify processes modifying the `NoAutoRebootWithLoggedOnUsers` value.
* Investigate the process lineage associated with any suspicious registry changes to determine if they originate from authorized system management software or unknown/malicious binaries.
* Tune the detection to exclude legitimate system management tools used in your environment to maintain low false positive rates.
