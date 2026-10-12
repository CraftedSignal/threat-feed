---
title: Remote System Discovery via PowerShell Adsisearcher
slug: 2026-10-adsisearcher-discovery
description: Adversaries and Red Teams utilize the [adsisearcher] PowerShell type accelerator to perform Active Directory reconnaissance by querying for domain computer objects.
date: "2026-10-12T17:56:08Z"
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
    evidence: The following analytic detects the use of the [Adsisearcher] type accelerator in PowerShell scripts to query Active Directory for domain computers.
    confidence_band: high
rules:
  - title: Detect Remote System Discovery via PowerShell Adsisearcher
    description: Detects the use of [adsisearcher] in PowerShell scripts to query Active Directory for domain computers, a technique used for reconnaissance.
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) on critical domain-joined assets
      owner: IT Operations
      due: 48h
      evidence: Required for visibility into adsisearcher usage
  hunt_leads:
    - lead: Search historical 4104 logs for adsisearcher patterns within the last 30 days
      technique_id: T1018
      data_needed:
        - ScriptBlockText
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Historical logs can reveal past enumeration attempts
---

Adversaries frequently use the [adsisearcher] type accelerator within PowerShell to interface directly with Active Directory services. By querying for objects where the category is set to 'computer', attackers can systematically enumerate domain-joined systems to map the network environment. This reconnaissance activity is a common precursor to lateral movement, allowing an attacker to identify high-value targets or pivot points. Because this technique relies on standard administrative tooling, it can often blend in with legitimate diagnostic scripts, making precise detection reliant on monitoring script execution patterns rather than the tool usage itself. Organizations should monitor for script blocks containing specific AD search parameters to identify unauthorized situational awareness efforts.

## Attack Chain

1. Attacker gains initial code execution on a domain-joined host via phishing or exploit.
2. Attacker initiates a PowerShell session to interact with the environment.
3. Attacker uses the [adsisearcher] type accelerator to create an AD search object.
4. Attacker defines a search filter targeting 'objectcategory=computer'.
5. Attacker executes search methods like 'findAll()' or 'findOne()' to retrieve the computer list.
6. Attacker processes the returned data to identify potential targets for lateral movement.
7. Attacker uses the compiled target list to initiate connection attempts (e.g., SMB, RDP, WinRM).
8. Attacker moves laterally to the identified targets to expand their presence in the network.

## Impact

Successful execution of this TTP facilitates comprehensive network mapping, significantly increasing the probability of effective lateral movement and privilege escalation. This enumeration allows attackers to bypass random search patterns and focus on critical infrastructure within the domain, potentially leading to unauthorized data access, ransomware deployment, or long-term persistence across multiple segments.

## Recommendation

1. Enable PowerShell Script Block Logging (Event ID 4104) across the environment to capture script contents for analysis.
2. Deploy the provided Sigma rule to your SIEM to detect the identified [adsisearcher] query pattern.
3. Investigate instances flagged by the detection, focusing on the user context and the surrounding script activity to differentiate between administrative troubleshooting and potential reconnaissance.
4. Implement strict monitoring on high-value systems where unauthorized Active Directory discovery would indicate a severe threat.
