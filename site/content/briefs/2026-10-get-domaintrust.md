---
title: Detection of PowerView Get-DomainTrust Reconnaissance
slug: 2026-10-get-domaintrust
description: Adversaries utilize the PowerView PowerShell module's Get-DomainTrust command to perform Active Directory reconnaissance, facilitating lateral movement planning by mapping domain trust relationships.
date: "2026-10-12T17:45:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - active-directory
  - discovery
  - powerview
  - powershell
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
    evidence: The following analytic identifies the execution of the Get-DomainTrust command from PowerView using PowerShell, which is used to gather domain trust information.
    confidence_band: high
rules:
  - title: Detect Get-DomainTrust Execution via PowerShell
    description: Detects the execution of the Get-DomainTrust command commonly used by PowerView for Active Directory reconnaissance.
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
    - action: Deploy Sigma detection rule for Get-DomainTrust command-line usage.
      owner: Detection Engineering
      due: 24h
      evidence: Source detection search.
  hunt_leads:
    - lead: Search for historical execution of 'Get-DomainTrust' or 'Get-NetDomainTrust' across existing EDR logs.
      technique_id: T1482
      data_needed:
        - Endpoint process command-line logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Tooling behavior documented in PowerView usage patterns.
---

This threat brief focuses on the use of the PowerView PowerShell utility to enumerate Active Directory domain trust relationships. Attackers frequently employ the Get-DomainTrust command during the discovery phase of an intrusion to gain a comprehensive understanding of the target network's topology. By identifying trust boundaries, adversaries can pinpoint paths for lateral movement and identify high-value targets within multi-domain or forest environments. This activity is a hallmark of post-exploitation reconnaissance and often precedes attempts to escalate privileges or compromise additional systems. Detection engineers should prioritize monitoring command-line telemetry for the invocation of PowerView modules, as these are rarely used in standard administrative workflows.

## Attack Chain

1. An attacker gains initial access to a workstation or server within the Windows domain.
2. The attacker performs local system enumeration to identify existing software and capabilities.
3. The attacker imports the PowerView PowerShell module into the current process memory.
4. The attacker executes the Get-DomainTrust command to query trust relationships between domains.
5. The command interacts with the Active Directory service to retrieve trust objects.
6. The adversary parses the output to identify reachable domains, transitive trusts, and SID filtering policies.
7. The attacker leverages this information to plan lateral movement tactics toward secondary domains or forest roots.
8. Final objective is achieved by using the discovered trust data to pivot into restricted environments.

## Impact

Successful execution allows attackers to map the architecture of an Active Directory environment, exposing security weaknesses in domain design. This reconnaissance can lead to unauthorized access across departmental boundaries, escalation of privileges, and widespread exfiltration if left undetected.

## Recommendation

Prioritize the implementation of EDR-based command-line monitoring to detect the usage of PowerView-related command strings.

- Deploy the provided Sigma rule to detect PowerShell command lines containing 'Get-DomainTrust'.
- Ensure Sysmon Event ID 1 (Process Creation) or Windows Event ID 4688 is ingested with full command-line arguments.
- Monitor for PowerShell execution contexts involving imported scripts or modules not identified in the organization's allowed software list.
- Investigate any user account associated with Get-DomainTrust execution for signs of credential compromise.
