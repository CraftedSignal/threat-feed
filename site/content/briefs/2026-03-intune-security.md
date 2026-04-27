---
title: CISA Urges Securing Microsoft Intune Systems Following Stryker Breach
slug: 2026-03-intune-security
description: CISA is urging US organizations to secure their Microsoft Intune systems due to a breach at Stryker, highlighting potential vulnerabilities in cloud-based device management that could lead to unauthorized access and control over managed devices.
date: "2026-03-19T12:09:13Z"
severities:
  - high
tags:
  - microsoft-intune
  - cloud-security
  - device-management
  - cisa-alert
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rxyoej/cisa_urges_us_orgs_to_secure_microsoft_intune/
  - https://www.bleepingcomputer.com/news/security/cisa-warns-businesses-to-secure-microsoft-intune-systems-after-stryker-breach/
rules:
  - title: Detect Suspicious PowerShell Commands from Intune
    description: Detects PowerShell commands executed from Microsoft Intune, which could indicate malicious activity such as malware deployment or configuration changes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Intune Configuration Changes via PowerShell
    description: Detects PowerShell commands modifying Intune configurations, which could indicate attacker activity
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 19, 2026, CISA released an advisory urging US organizations to secure their Microsoft Intune systems following a breach at Stryker. While specific technical details of the Stryker breach are not provided in the source, the advisory suggests that vulnerabilities exist within Intune configurations or related access controls that, if exploited, could allow unauthorized access to and control over managed devices and sensitive data. The alert emphasizes the importance of hardening Intune…
