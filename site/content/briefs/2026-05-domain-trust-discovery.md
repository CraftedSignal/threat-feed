---
title: Enumerating Domain Trusts via DSQUERY.EXE
slug: 2026-05-domain-trust-discovery
description: Adversaries may use the `dsquery.exe` command-line utility to enumerate trust relationships for lateral movement in Windows multi-domain environments.
date: "2026-05-04T14:17:05Z"
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
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
affected_os:
  - Windows
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
  - title: Detect Enumerating Domain Trusts via DSQUERY.EXE
    description: Detects the execution of dsquery.exe with arguments used to enumerate domain trusts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1482
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious DSQUERY Execution
    description: Detects suspicious executions of dsquery.exe based on command-line arguments.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `dsquery.exe` utility is a command-line tool in Windows used to query Active Directory. Attackers may leverage `dsquery.exe` to discover domain trust relationships within a Windows environment, mapping out potential lateral movement paths. This discovery is often an early stage in reconnaissance, before an attacker attempts to move laterally to other systems. This activity can be detected across various endpoint detection platforms including Elastic Defend, CrowdStrike, Microsoft Defender XDR, and SentinelOne. This activity is not inherently malicious, as administrators also use it for legitimate purposes.

## Attack Chain

1. An attacker gains initial access to a compromised host within the target environment.
2. The attacker executes `dsquery.exe` with the argument `objectClass=trustedDomain` to enumerate domain trusts.
3. The command execution is logged by endpoint detection and response (EDR) solutions or Windows Security Event Logs.
4. The attacker parses the output of the `dsquery.exe` command to identify trusted domains and their attributes.
5. The attacker uses the discovered trust information to plan lateral movement strategies.
6. The attacker attempts to authenticate to other systems within the trusted domains using stolen credentials or other exploits.

## Impact

Successful enumeration of domain trusts enables attackers to map out the Active Directory environment and identify potential pathways for lateral movement. While the enumeration itself is low impact, it facilitates subsequent actions like credential theft, privilege escalation, and data exfiltration. This can lead to widespread compromise across the organization, impacting numerous systems and sensitive data.

## Recommendation

*   Deploy the Sigma rule "Detect Enumerating Domain Trusts via DSQUERY.EXE" to your SIEM and tune for your environment.
*   Investigate any execution of `dsquery.exe` with the argument `objectClass=trustedDomain` to identify potentially malicious activity.
*   Monitor process execution events for `dsquery.exe` to detect suspicious command-line arguments and execution patterns.
