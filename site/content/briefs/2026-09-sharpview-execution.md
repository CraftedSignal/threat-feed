---
title: SharpView Reconnaissance Tool Execution
slug: 2026-09-sharpview-execution
description: Adversaries utilize the SharpView C# port of PowerView to perform extensive Active Directory reconnaissance, domain enumeration, and discovery of sensitive network objects.
date: "2026-09-03T13:45:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - discovery
  - active-directory
  - windows
  - hacktool
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
    evidence: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069.002
    technique_name: 'Permission Groups Discovery: Domain Groups'
    evidence: The tool facilitates discovery within Active Directory environments, allowing threat actors to enumerate group memberships.
    confidence_band: high
rules:
  - title: Detect SharpView Execution
    description: Detects execution of the SharpView reconnaissance tool via process name or recognized functional command line arguments.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1033
      - T1049
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
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 24h
      evidence: SigmaHQ source repository
  hunt_leads:
    - lead: Search logs for unusual command line arguments matching SharpView functions
      technique_id: T1049
      data_needed:
        - Process creation logs with full command line
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of SharpView command arguments
  mitigation_plan:
    - priority: medium_term
      action: Restrict unprivileged access to Active Directory via LDAP
      owner: IT Operations
      addresses: General AD Reconnaissance
      evidence: Standard security hardening practices
---

SharpView is a C# implementation of the popular PowerShell-based reconnaissance tool PowerView. It is designed to facilitate discovery within Active Directory environments, allowing threat actors to enumerate domain resources, group memberships, trust relationships, and user privileges without relying on the PowerShell execution environment, which may be heavily monitored by endpoint security solutions. The tool provides a wide array of functions to identify interesting targets such as Kerberoastable accounts, local administrative access, and sensitive share permissions. Defenders should note that SharpView is frequently employed during the post-exploitation phase to map the network topology and identify high-value targets for lateral movement and privilege escalation. Its execution typically results in extensive process-based activity as the tool queries domain controllers and performs automated network enumeration.

## Attack Chain

1. Initial access is established through credential theft or exploitation.
2. The attacker stages the SharpView.exe binary on the compromised host.
3. The adversary executes SharpView via command line with specific arguments (e.g., Get-DomainUser, Find-LocalAdminAccess).
4. The tool leverages LDAP and RPC protocols to query Active Directory domain controllers.
5. It enumerates GPOs, trust relationships, and domain group memberships (e.g., Get-DomainGPO, Get-NetGroupMember).
6. The tool executes local or remote reconnaissance commands such as Invoke-Sharefinder or Invoke-Kerberoast.
7. Enumeration results are captured and either written to the local disk or exfiltrated via the command line interface.
8. The final objective is typically the identification of domain administrator accounts or vulnerable service tickets to facilitate credential harvesting or lateral movement.

## Impact

Successful execution of SharpView provides attackers with a comprehensive blueprint of the organization's Active Directory structure. This significantly increases the risk of successful privilege escalation, domain-wide compromise, and data exfiltration. The tool's ability to automate complex queries against domain controllers facilitates rapid discovery, shortening the attacker's dwell time and enabling targeted attacks against specific users or high-value infrastructure.

## Recommendation

* Deploy the provided Sigma rule to detect the execution of SharpView.exe or its common functional arguments.
* Monitor for abnormal command line arguments indicative of Active Directory discovery, specifically those referencing "Find-" or "Get-Domain" tasks.
* Enable Sysmon Event ID 1 (Process Creation) to capture detailed command line arguments used by potential reconnaissance tools.
* Restrict the ability of standard user accounts to perform LDAP queries against domain controllers.
* Monitor for high volumes of LDAP traffic originating from non-administrative endpoints.
