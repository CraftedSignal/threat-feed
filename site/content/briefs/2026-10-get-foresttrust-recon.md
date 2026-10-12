---
title: Detection of Get-ForestTrust PowerShell Reconnaissance
slug: 2026-10-get-foresttrust-recon
description: This detection identifies the execution of the Get-ForestTrust PowerShell command, which adversaries use to map Active Directory forest trust relationships for lateral movement and privilege escalation.
date: "2026-10-12T17:45:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - active-directory
  - discovery
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
    evidence: The following analytic detects the execution of the Get-ForestTrust command via PowerShell, commonly used by adversaries to gather domain trust information.
    confidence_band: high
references:
  - https://powersploit.readthedocs.io/en/latest/Recon/Get-ForestTrust/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1482/T1482.yaml#L130
rules:
  - title: Detect Get-ForestTrust Execution
    description: Detects the execution of Get-ForestTrust via PowerShell or CMD which indicates AD reconnaissance
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1482
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
    - action: Deploy the Sigma rule for Get-ForestTrust execution
      owner: Detection Engineering
      due: 48h
      evidence: Source provides search logic for identification
  hunt_leads:
    - lead: Search historical logs for 'get-foresttrust' in command lines
      technique_id: T1482
      data_needed:
        - Process creation logs with full command lines
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique is a known indicator of reconnaissance
---

This threat brief focuses on the detection of the Get-ForestTrust PowerShell command, a reconnaissance technique frequently utilized by adversaries to enumerate trust relationships within an Active Directory environment. By identifying the execution of this specific command, security teams can detect attackers attempting to map out the network structure, which is a precursor to lateral movement and privilege escalation efforts. The detection methodology targets command-line executions of PowerShell or Command Prompt containing the string 'get-foresttrust', leveraging EDR telemetry to provide visibility into potential reconnaissance activity. Monitoring for this behavior is critical, as it rarely occurs in standard administrative tasks and often indicates an attacker's effort to understand the organizational structure post-compromise.

## Attack Chain

1. Attacker gains initial access to an endpoint within the domain.
2. Attacker performs local enumeration to identify user context and available modules.
3. Attacker imports or executes PowerShell-based reconnaissance modules (e.g., PowerSploit).
4. Attacker executes the Get-ForestTrust command to query Active Directory.
5. The command returns detailed information about forest trusts and domain relationships.
6. Attacker leverages identified trust relationships to plan lateral movement to trusted domains.
7. Attacker proceeds to authenticate to target systems in trusted domains using harvested credentials.

## Impact

Successful exploitation of Active Directory trust enumeration allows attackers to map the extent of the forest, identifying paths for privilege escalation and lateral movement. This reconnaissance significantly increases the speed and success of follow-on attacks, potentially leading to unauthorized access to sensitive domains or the entire Active Directory forest, facilitating further data exfiltration or ransomware deployment.

## Recommendation

Prioritized actions for detection engineering teams:

- Deploy the Sigma rules below to your SIEM to monitor for 'get-foresttrust' in command-line arguments.
- Enable Sysmon Event ID 1 (Process Creation) or Security Event ID 4688 to capture complete command-line executions.
- Map endpoint process logs to the CIM 'Processes' node to support the detection logic.
- Investigate any hits by reviewing the parent process lineage and user context via the identified drilldown searches.
