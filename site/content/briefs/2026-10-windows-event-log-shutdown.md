---
title: Detection of Windows Event Log Service Shutdown
slug: 2026-10-windows-event-log-shutdown
description: Attackers often terminate the Windows Event Log service, documented via Event ID 1100, to disrupt auditing and obscure malicious post-exploitation activities.
date: "2026-10-12T18:05:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - log-manipulation
  - endpoint-security
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: The following analytic detects the shutdown of the Windows Event Log service by leveraging Windows Event ID 1100.
    confidence_band: high
references:
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1100
  - https://attack.mitre.org/techniques/T1070/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md
rules:
  - title: Detect Windows Event Log Service Shutdown
    description: Detects the shutdown of the Windows Event Log service using Event ID 1100, which may indicate an attempt to disable security logging.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1070.001
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
    - action: Deploy Event ID 1100 monitoring for endpoints.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic metadata.
  hunt_leads:
    - lead: Search for Event ID 1100 not preceded by system restart logs.
      technique_id: T1070.001
      data_needed:
        - Windows Event Logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source documentation on monitoring for malicious shutdown.
  mitigation_plan:
    - priority: medium
      action: Review access control for service management permissions.
      owner: IT Operations
      addresses: T1070.001
      evidence: General security best practices.
---

The Windows Event Log service is responsible for recording significant events on a system, including security-related actions. Attackers frequently target this service to disable or clear event logs as a means of defense evasion, ensuring their malicious footprints are not recorded or are erased from the system. This activity is logged by the operating system using Event ID 1100 in the Security event log. While this event occurs during legitimate system shutdowns or maintenance windows, an unexpected shutdown of this service is a strong indicator of an attempt to blind security monitoring solutions. Detecting this activity is vital for identifying adversaries attempting to cover their tracks during ransomware deployments or other prolonged intrusive campaigns. Defenders must distinguish between planned service stoppages and unauthorized attempts to manipulate host logging.

## Attack Chain

1. Attacker gains administrative access to the targeted Windows host.
2. Attacker enumerates running services to identify the Event Log service.
3. Attacker uses built-in tools or custom malware to issue a service stop command (e.g., net stop eventlog).
4. The operating system writes Event ID 1100 to the Security log to document the service shutdown.
5. The attacker executes additional malicious commands or tools, knowing that no new security logs will be generated.
6. The attacker performs the final objective, such as credential theft or data exfiltration.
7. The attacker may attempt to clear existing logs or destroy evidence before exiting the environment.

## Impact

Successful termination of the Windows Event Log service prevents the generation of forensic audit trails, significantly increasing the time required for responders to detect and investigate a compromise. This technique is commonly associated with ransomware operations and lateral movement, where the attacker seeks to remain undetected by security teams. Failure to monitor this event may allow attackers to operate with reduced visibility for an extended period, leading to unauthorized data access and system damage.

## Recommendation

* Enable the ingestion of Windows Security logs, specifically focusing on Event ID 1100, into your SIEM platform.
* Deploy the provided Sigma rule to alert on unexpected Windows Event Log service shutdowns that do not correlate with scheduled system maintenance or known administrative windows.
* Investigate all instances of Event ID 1100 that occur outside of a system-wide shutdown or reboot event to verify the legitimacy of the process.
* Implement restrictive service control permissions via Group Policy to prevent unauthorized users from stopping critical security-related services.
