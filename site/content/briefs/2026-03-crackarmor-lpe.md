---
title: 'CrackArmor: AppArmor Flaws Enable Local Privilege Escalation'
slug: 2026-03-crackarmor-lpe
description: Qualys discovered critical vulnerabilities in AppArmor, enabling local privilege escalation to root on vulnerable Linux systems.
date: "2026-03-17T12:00:00Z"
severities:
  - critical
tags:
  - apparmor
  - privilege-escalation
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rublnj/crackarmor_critical_apparmor_flaws_enable_local/
  - https://blog.qualys.com/vulnerabilities-threat-research/2026/03/12/crackarmor-critical-apparmor-flaws-enable-local
rules:
  - title: Detect AppArmor Profile Loading via apparmor_parser
    description: Detects execution of apparmor_parser, which is used to load AppArmor profiles, potentially loading malicious profiles.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of AppArmor Profiles
    description: Detects attempts to modify AppArmor profiles, which could indicate an attempt to introduce malicious rules or bypass existing restrictions.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

In March 2026, Qualys disclosed a set of critical vulnerabilities collectively named "CrackArmor" affecting AppArmor, a Linux kernel security module. These flaws allow a local attacker to escalate privileges to root. While specific CVEs were not detailed in the initial Reddit post, the Qualys blog (linked in the source) will likely contain them. The vulnerabilities stem from weaknesses in AppArmor's parsing and enforcement mechanisms, allowing for crafted AppArmor profiles or interactions with…
