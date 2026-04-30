---
title: Ubuntu 24.04 Snapd Local Privilege Escalation (CVE-2026-3888)
slug: 2026-03-snapd-lpe
description: CVE-2026-3888 allows a local attacker to escalate privileges to root on Ubuntu 24.04 systems due to a vulnerability in the snapd service.
date: "2026-03-19T00:38:41Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - snapd
  - ubuntu
  - CVE-2026-3888
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.reddit.com/r/netsec/comments/1rxlr0y/ubtuntu_2404_snapd_local_privilege_escalation/
  - https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root
rules:
  - title: Detect Suspicious Snap Package Installation
    description: Detects attempts to install snap packages from unusual locations, potentially indicating exploitation of CVE-2026-3888.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Snapd Spawning Root Shell
    description: Detects snapd spawning a shell as root, which can indicate privilege escalation.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A local privilege escalation vulnerability, identified as CVE-2026-3888, affects Ubuntu 24.04 installations due to a flaw within the snapd service. This vulnerability allows a malicious local user to gain root privileges on a vulnerable system. The Qualys Research Team discovered and reported the vulnerability on March 17, 2026. Defenders should prioritize patching vulnerable systems to prevent potential exploitation. The vulnerability's impact is significant, as successful exploitation grants…
