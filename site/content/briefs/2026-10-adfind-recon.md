---
title: Adversary Abuse of AdFind for Active Directory Discovery
slug: 2026-10-adfind-recon
description: Threat actors, including Wizard Spider and FIN6, frequently abuse the legitimate AdFind.exe utility to perform unauthorized Active Directory reconnaissance to facilitate lateral movement and privilege escalation.
date: "2026-10-12T18:00:52Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Conti
  - Wizard Spider
tags:
  - discovery
  - active-directory
  - reconnaissance
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: Adversaries leverage specific flags to enumerate domain trusts, user accounts, and group memberships, facilitating lateral movement and privilege escalation.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087.002
    technique_name: 'Account Discovery: Domain Account'
    evidence: AdFind.exe is a powerful tool often used by threat actors like Wizard Spider and FIN6 to gather sensitive AD information.
    confidence_band: high
rules:
  - title: Detect AdFind.exe Execution for AD Discovery
    description: Detects the execution of AdFind.exe with command-line arguments indicative of Active Directory discovery and enumeration
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for AdFind activity
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line arguments used for discovery
---

AdFind.exe is a legitimate, powerful command-line tool developed by Joeware, intended for Active Directory administration and management. However, its capability to query domain structures, trust relationships, user accounts, and group memberships makes it a high-value target for adversaries. Threat actors such as Wizard Spider and FIN6 have integrated AdFind into their post-exploitation toolkits to conduct rapid domain-wide discovery. Because the tool is often used for legitimate administrative tasks, defenders must distinguish between sanctioned management activity and adversary reconnaissance by analyzing specific command-line arguments, parent process patterns, and endpoint telemetry. Successfully executing these queries allows an attacker to map the target environment, identify high-value targets, and prepare for lateral movement or privilege escalation.

## Attack Chain

1. Initial access is established on an endpoint through a variety of vectors (e.g., phishing, exploit).
2. The attacker performs initial reconnaissance to locate and execute available discovery tools.
3. AdFind.exe is deployed to the endpoint, often residing in temporary directories or renamed to evade basic detection.
4. The actor executes AdFind.exe with specific command-line arguments (e.g., `-f`, `-sc`, or `-gcb`) to initiate AD enumeration.
5. The utility queries domain controllers via LDAP to extract information about trusts, user objects, and groups.
6. The resulting enumeration output is captured, often redirected to a local file or exfiltrated through established C2 channels.
7. The collected directory information is analyzed by the attacker to identify targets for lateral movement (e.g., domain admin accounts).
8. The final objective of moving laterally or escalating privileges is pursued based on the intelligence gathered from the AdFind output.

## Impact

Successful reconnaissance with AdFind provides attackers with a comprehensive map of the Active Directory environment. This enables highly targeted lateral movement and privilege escalation attacks. Historically, this activity has been observed as a precursor to large-scale ransomware campaigns, including BlackSuit, and is a hallmark of sophisticated persistent threats aiming to disrupt business operations or steal sensitive credentials.

## Recommendation

* Deploy the Sigma rule below to monitor for suspicious command-line execution patterns associated with AdFind.
* Establish a baseline of authorized administrative tools and service accounts to filter out legitimate AdFind usage from the detection logic.
* Ingest process-creation logs (Sysmon Event ID 1 or Windows Security 4688) into the SIEM and ensure command-line logging is enabled.
* Monitor for non-standard parent processes spawning AdFind.exe, which is a common indicator of automated post-exploitation activity.
