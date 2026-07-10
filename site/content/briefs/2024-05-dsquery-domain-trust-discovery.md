---
title: Enumerating Domain Trusts via DSQUERY.EXE
slug: 2024-05-dsquery-domain-trust-discovery
description: Adversaries may use dsquery.exe to enumerate domain trusts, which can be leveraged for lateral movement in Windows multi-domain environments.
date: "2024-05-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - domain-trust
  - windows
vendors:
  - Microsoft
products:
  - Windows
  - Active Directory
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)
  - https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944
rules:
  - title: Detect Domain Trust Discovery via DSQUERY
    description: Detects the execution of dsquery.exe with arguments used for domain trust discovery.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1018
      - T1482
    data_sources:
      - process_creation
      - windows
  - title: Detect Domain Trust Discovery via DSQUERY (Sysmon)
    description: Detects the execution of dsquery.exe with arguments used for domain trust discovery via Sysmon.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1018
      - T1482
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `dsquery.exe` is a command-line tool used in Windows environments to query Active Directory. While legitimate uses exist, adversaries can use it to enumerate domain trusts within a multi-domain forest. By identifying trust relationships, attackers gain insights into potential lateral movement paths. This activity, while not inherently malicious, serves as a reconnaissance step that could precede more harmful actions, so its detection is crucial for early threat mitigation. This technique can be used to gain knowledge about the target environment, allowing the attacker to make informed decisions about further actions. The rule detects the execution of `dsquery.exe` with specific arguments related to discovering domain trusts. The Elastic rule ID is 06a7a03c-c735-47a6-a313-51c354aef6c3, updated on 2026/04/07.

## Attack Chain

1.  **Initial Access:** Adversary gains initial access to a system within the target network.
2.  **Credential Access:** The attacker may use credential harvesting tools to obtain valid credentials.
3.  **Discovery:** The adversary executes `dsquery.exe` with the argument `objectClass=trustedDomain` to enumerate domain trusts.
4.  **Lateral Movement:** Based on the discovered trust relationships, the adversary attempts to move laterally to other systems or domains.
5.  **Privilege Escalation:** The adversary escalates privileges on the target system.
6.  **Data Exfiltration:** The adversary exfiltrates sensitive data from compromised systems.

## Impact

Successful enumeration of domain trusts can lead to lateral movement across the network, potentially compromising multiple systems and domains. This can result in data breaches, system disruption, and financial losses. While the enumeration itself is not directly damaging, it provides crucial information for attackers to plan and execute further malicious activities. The impact is elevated when combined with stolen credentials or unpatched vulnerabilities.

## Recommendation

*   Deploy the Sigma rule "Detect Domain Trust Discovery via DSQUERY" to your SIEM and tune for your environment to detect the execution of `dsquery.exe` with arguments used for domain trust discovery.
*   Enable Sysmon process-creation logging to activate the rules above.
*   Review process execution logs for instances of `dsquery.exe` with the `objectClass=trustedDomain` argument, as highlighted in the rule.
*   Monitor network connections originating from systems where `dsquery.exe` was executed, looking for suspicious lateral movement activity.
