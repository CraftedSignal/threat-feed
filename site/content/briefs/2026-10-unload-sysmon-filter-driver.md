---
title: Defense Evasion via Sysmon Driver Unloading
slug: 2026-10-unload-sysmon-filter-driver
description: Adversaries utilize the fltMC.exe utility to unload the Sysmon filter driver, effectively blinding security monitoring and suppressing telemetry generation to facilitate further malicious activity.
date: "2026-10-12T17:59:59Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Microsoft
products:
  - Sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: By unloading this driver, attackers can effectively blind security monitoring systems, allowing them to perform subsequent malicious activities without generating telemetry logs.
    confidence_band: high
rules:
  - title: Detect Sysmon Filter Driver Unloading via fltMC.exe
    description: Detects the use of fltMC.exe to unload the Sysmon driver, which blinds security monitoring.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for Sysmon driver unloading
      owner: Detection Engineering
      due: 24h
      evidence: Source document highlights this as a critical evasion technique
  hunt_leads:
    - lead: Search historical logs for fltMC.exe usage targeting SysmonDrv
      technique_id: T1562.001
      data_needed:
        - Process creation telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This technique is a known mechanism for blinding monitoring systems
  mitigation_plan:
    - priority: immediate
      action: Restrict administrative rights on endpoints
      owner: IT Operations
      addresses: T1562.001
      evidence: Technique requires administrative privileges to execute
---

Adversaries often attempt to disable or bypass security controls to minimize their footprint during post-exploitation activities. A documented technique involves the use of the built-in Windows utility `fltMC.exe` to unload the Sysmon filter driver (`SysmonDrv`). By successfully executing this command, an attacker forces the Sysmon service to stop recording system activity, effectively blinding the security operations team to subsequent actions such as process execution, file modifications, and network connections.

This technique is significant because it represents a deliberate effort to neutralize endpoint detection and response capabilities. Once the driver is unloaded, the endpoint stops generating critical telemetry, providing the attacker with a window of opportunity to move laterally, escalate privileges, or exfiltrate data without leaving an audit trail in the standard Sysmon operational logs. Defenders must monitor for the invocation of `fltMC.exe` with arguments specifically targeting the Sysmon driver.

## Attack Chain

1. Attacker gains initial access or achieves sufficient local administrative privileges on a Windows host.
2. Attacker identifies that Sysmon is active and providing monitoring coverage.
3. Attacker executes `fltMC.exe` via the command line with administrative tokens.
4. Attacker provides the `unload` argument to the filter driver management utility.
5. Attacker specifies `SysmonDrv` as the target for the unloading operation.
6. The system processes the request, unhooking the Sysmon filter from the kernel.
7. Sysmon event logging ceases, effectively blinding the host to further malicious activity.
8. Attacker proceeds with follow-on objectives (e.g., credential theft, persistence, or data staging) while the host remains unmonitored.

## Impact

The successful execution of this technique results in the total loss of visibility from the Sysmon service on the targeted endpoint. This lack of telemetry prevents the identification of further attacker actions, significantly increasing the risk of data breaches, unauthorized persistent access, and undetected privilege escalation. If left unmonitored, an attacker can maintain control over the compromised host indefinitely without triggering further security alerts based on Sysmon telemetry.

## Recommendation

* Deploy the Sigma rule below to detect attempts to unload the Sysmon driver using `fltMC.exe`.
* Ensure that Sysmon process creation logs (Event ID 1) are ingested into the SIEM and mapped to the Endpoint data model.
* Enable alerts for `fltMC.exe` activity, particularly when the command line includes `unload` and `SysmonDrv`, as this is highly anomalous in production environments.
* Restrict administrative privileges to prevent unauthorized users from executing filter management utilities.
