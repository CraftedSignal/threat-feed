---
title: Active Directory Account Discovery via PowerShell Adsisearcher
slug: 2026-10-adsisearcher-discovery
description: Adversaries utilize the PowerShell [adsisearcher] type accelerator to perform Active Directory domain user enumeration, facilitating reconnaissance and lateral movement.
date: "2026-10-12T17:35:58Z"
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
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: The following analytic detects the use of the [Adsisearcher] type accelerator in PowerShell to query Active Directory for domain users.
    confidence_band: high
rules:
  - title: Detect PowerShell Adsisearcher Account Discovery
    description: Detects the use of the [adsisearcher] type accelerator combined with objectcategory=user and .findAll() to query Active Directory domain users
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.002
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) on critical domain servers
      owner: IT Operations
      due: 72h
      evidence: Source requirement for analytic implementation
  hunt_leads:
    - lead: Search for historical Event ID 4104 logs containing [adsisearcher] or .findAll()
      technique_id: T1087.002
      data_needed:
        - PowerShell Operational Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic describes typical adversary discovery behavior
  mitigation_plan:
    - priority: medium_term
      action: Restrict non-administrative user permissions to query Active Directory via LDAP
      owner: Identity Team
      addresses: T1087.002
      evidence: Standard security hardening practice
---

Adversaries and Red Teams frequently leverage the [adsisearcher] type accelerator in PowerShell to perform unauthorized discovery of Active Directory domain users. This technique allows an attacker to programmatically query the directory to build a map of user objects within the domain. By using filters such as objectcategory=user and the .findAll() method, attackers can efficiently extract a comprehensive list of accounts. This reconnaissance activity is a critical precursor to further malicious actions, including targeted credential harvesting, privilege escalation, and lateral movement. Defenders should monitor PowerShell Script Block Logging (EventCode 4104) to identify these distinct patterns in script execution. This activity has been observed in various adversary campaigns, including those associated with Industroyer2 and Lapsus$ style actors.

## Attack Chain

1. Initial access is established via credential theft or exploit, providing the attacker with a low-privileged user context on a domain-joined machine.
2. The attacker launches a PowerShell session, often hidden or obfuscated, to avoid immediate detection by legacy command-line logging.
3. The attacker loads the [adsisearcher] type accelerator within a script block to interface directly with the Active Directory service via LDAP.
4. The script defines a filter, specifically objectcategory=user, to isolate user objects from other directory entries like computers or organizational units.
5. The .findAll() method is executed to execute the query against the domain controller and retrieve all matched results.
6. Results are returned to the PowerShell session, where the attacker may format the output or export the list for further analysis.
7. The attacker analyzes the enumerated user data to identify high-value accounts, such as domain admins or service accounts.
8. Final objective is achieved as the attacker uses the discovered account list to perform password spraying or targeted exploitation.

## Impact

Successful account discovery provides attackers with high-fidelity intelligence regarding the target environment's structure. This visibility significantly increases the likelihood of success for subsequent attacks, as it allows attackers to bypass generic scanning and perform surgical strikes against privileged accounts. Failure to detect this activity early can lead to large-scale credential theft, unauthorized access to sensitive systems, and persistence in the victim's domain.

## Recommendation

Prioritize the implementation of PowerShell Script Block Logging (EventCode 4104) across all domain-joined Windows endpoints. Deploy the provided Sigma rule to your SIEM to alert on the specific combination of [adsisearcher] and .findAll() patterns. If the alert triggers, isolate the affected host, identify the user context executing the script, and review the host's recent activities for signs of follow-on lateral movement or credential access attempts.
