---
title: xrdp Privilege Escalation Vulnerability (CVE-2026-32107)
slug: 2026-04-xrdp-privesc
description: xrdp versions through 0.10.5 are vulnerable to a privilege escalation flaw (CVE-2026-32107) where improper privilege management during the privilege drop process could allow an authenticated local attacker to escalate privileges to root and execute arbitrary code.
date: "2026-04-17T20:16:33Z"
severities:
  - high
tags:
  - xrdp
  - privilege-escalation
  - cve-2026-32107
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-32107
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32107
  - https://github.com/neutrinolabs/xrdp/releases/tag/v0.10.6
  - https://github.com/neutrinolabs/xrdp/security/advisories/GHSA-p5m6-7m43-pjv9
ioc_counts:
  email: 1
rules:
  - title: Suspicious Process Execution from xrdp Session
    description: Detects suspicious processes spawned from an xrdp session, potentially indicating exploitation of CVE-2026-32107.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Elevated Privileges Execution from xrdp
    description: Detects execution of commands with elevated privileges (sudo, su) from xrdp session.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-32107 affects xrdp, an open-source Remote Desktop Protocol (RDP) server. Specifically, versions up to and including 0.10.5 contain a flaw in the session execution component. The vulnerability stems from the improper handling of errors during the privilege drop process. This allows a local, authenticated attacker to potentially escalate their privileges to root. Successful exploitation requires an additional, unspecified exploit to trigger the vulnerable code path. The vulnerability has…
