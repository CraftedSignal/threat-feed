---
title: RegPwn Windows Local Privilege Escalation Vulnerability
slug: 2024-05-regpwn-lpe
description: RegPwn is a now-fixed local privilege escalation vulnerability in Windows that allowed an attacker to gain elevated privileges.
date: "2026-03-13T17:12:22Z"
severities:
  - high
tags:
  - windows
  - lpe
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.reddit.com/r/netsec/comments/1rstavq/regpwn_windows_lpe_vulnerability_now_fixed/
  - https://www.mdsec.co.uk/2026/03/rip-regpwn/
rules:
  - title: Detect Suspicious Registry Modifications for Privilege Escalation
    description: Detects suspicious registry modifications that may indicate an attempt to exploit a privilege escalation vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Potential Exploitation via Uncommon Processes in System Directories
    description: This rule detects the execution of uncommon or suspicious processes within system directories.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The RegPwn vulnerability was a local privilege escalation (LPE) issue affecting Windows operating systems. Although the specifics of the vulnerability aren't detailed in the provided context, LPE vulnerabilities generally allow an attacker who already has some level of access to a system to gain higher-level privileges, potentially SYSTEM. The provided information indicates that the vulnerability has been patched, so the primary concern is identifying systems that may not have received the…
