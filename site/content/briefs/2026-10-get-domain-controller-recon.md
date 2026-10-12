---
title: Detection of Active Directory Domain Controller Discovery via PowerShell
slug: 2026-10-get-domain-controller-recon
description: This detection targets the execution of the PowerShell command 'Get-DomainController', often used by attackers to enumerate domain infrastructure as part of Active Directory discovery.
date: "2026-10-12T17:46:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - active-directory
  - reconnaissance
  - discovery
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: The following analytic detects the execution of powershell.exe with the Get-DomainController command, which is used to discover remote systems within a Windows domain.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1018/
  - https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainController/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1018/T1018.yaml#L372
rules:
  - title: Detect Get-DomainController PowerShell Execution
    description: Detects the execution of PowerShell with the Get-DomainController command, a common technique for Active Directory discovery.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule and enable command-line logging for PowerShell.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic guidance for implementing process-based detection.
  hunt_leads:
    - lead: Search for historical execution of 'Get-DomainController' to baseline known admin activity.
      technique_id: T1018
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Active Directory Discovery is a common precursor to lateral movement.
---

The 'Get-DomainController' command is a function within the PowerSploit framework used to discover the identity and location of domain controllers within a Windows domain. Adversaries often execute this command as part of the initial reconnaissance phase to map Active Directory environments and identify high-value targets for subsequent lateral movement. This detection analytic focuses on identifying instances where 'powershell.exe' is invoked with command-line arguments containing this specific function name. By monitoring for this activity, defenders can detect potential internal reconnaissance attempts before the attacker progresses to credential harvesting or privilege escalation. This activity is considered a high-signal indicator of unauthorized enumeration within an Active Directory environment.

## Impact

Successful reconnaissance allows attackers to gain situational awareness of the domain architecture, which is a precursor to lateral movement, data exfiltration, or domain-wide compromise. Unauthorized discovery of domain infrastructure can lead to the identification of critical assets and further exploitation of the network.

## Recommendation

* Deploy the Sigma rule below to detect 'Get-DomainController' usage in PowerShell command lines.
* Ingest process-creation telemetry (Sysmon Event ID 1 or Windows Security Event ID 4688) into the SIEM and ensure the 'CommandLine' field is captured.
* Tune the detection by creating an allowlist for known administrative accounts or authorized security testing tools that may legitimately use PowerSploit functions.
