---
title: Detection of Unconstrained Delegation Discovery via PowerShell
slug: 2026-09-ad-delegation-discovery
description: Adversaries are utilizing the Get-ADComputer PowerShell cmdlet to enumerate Active Directory objects configured for unconstrained delegation, a reconnaissance step often preceding ticket-based credential theft.
date: "2026-09-03T13:41:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - discovery
  - active-directory
  - powershell
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: Detects the use of the Get-ADComputer cmdlet in order to identify systems which are configured for unconstrained delegation.
    confidence_band: high
rules:
  - title: Detect Unconstrained Delegation Discovery via Get-ADComputer
    description: Detects the use of the Get-ADComputer cmdlet in order to identify systems which are configured for unconstrained delegation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - reconnaissance
    techniques:
      - T1018
      - T1558
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all domain-joined assets.
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into Get-ADComputer cmdlet execution.
  hunt_leads:
    - lead: Search for Event ID 4104 logs containing Get-ADComputer with parameters related to delegation.
      technique_id: T1018
      data_needed:
        - PowerShell Script Block logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Detection logic matches common discovery patterns.
---

This threat brief identifies reconnaissance activity targeting Active Directory configurations. Attackers leverage the Get-ADComputer cmdlet to scan for machines with specific attributes that indicate unconstrained delegation. Unconstrained delegation allows a server to impersonate a domain user to any other service in the forest, making these systems high-value targets for attackers seeking to escalate privileges or move laterally through the domain. By identifying these computers, an attacker can plan credential harvesting operations, such as capturing TGTs from a compromised service account. Defenders should monitor PowerShell Script Block logs for queries specifically filtering for delegation-related LDAP flags or properties. This activity is a common precursor to advanced lateral movement and credential access techniques in Windows environments.

## Attack Chain

1. Attacker establishes initial access on a domain-joined machine.
2. Attacker loads the ActiveDirectory PowerShell module.
3. Attacker executes Get-ADComputer with flags to query TrustedForDelegation properties.
4. Attacker parses output to identify specific high-value targets.
5. Attacker attempts to compromise the identified service account or host.
6. Attacker harvests credentials or impersonates users via the delegation vulnerability.
7. Attacker proceeds to lateral movement or further domain privilege escalation.

## Impact

Successful discovery leads to the identification of critical infrastructure in a Windows domain environment. If exploited, attackers can gain the ability to impersonate domain users, leading to widespread unauthorized access, privilege escalation, and potential full domain compromise.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) across all domain-joined Windows endpoints.
- Deploy the provided Sigma rule to detect suspicious Get-ADComputer cmdlet usage focused on delegation properties.
- Audit high-privilege service accounts and limit the use of unconstrained delegation where not strictly required by application architecture.
