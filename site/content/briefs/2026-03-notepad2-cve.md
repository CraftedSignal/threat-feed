---
title: Notepad2 PROPSYS.dll Uncontrolled Search Path Vulnerability (CVE-2026-4545)
slug: 2026-03-notepad2-cve
description: CVE-2026-4545 describes a vulnerability in Flos Freeware Notepad2 4.2.25, where manipulating PROPSYS.dll leads to an uncontrolled search path, potentially allowing a local attacker to execute arbitrary code with elevated privileges.
date: "2026-03-23T14:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - uncontrolled search path
  - privilege escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4545
  - https://vuldb.com/?ctiid.352372
  - https://vuldb.com/?id.352372
  - https://vuldb.com/?submit.774752
rules:
  - title: Detect Notepad2 Loading DLL from Suspicious Path
    description: Detects Notepad2 loading a DLL from a non-standard directory, which could indicate an attempt to exploit CVE-2026-4545 via DLL hijacking.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - windows
  - title: Detect PROPSYS.dll Load from Unusual Location
    description: Detects PROPSYS.dll being loaded from a non-standard location, potentially indicating exploitation of CVE-2026-4545
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - windows
rules_count: 2
---

A security flaw, identified as CVE-2026-4545, exists within Flos Freeware Notepad2 version 4.2.25. The vulnerability resides in an unspecified function within the PROPSYS.dll library, leading to an uncontrolled search path issue. Exploitation of this flaw requires local access and is considered to have a high degree of complexity, meaning a successful attack is difficult to execute. The vendor, Flos Freeware, was notified about this vulnerability, but has not responded. Successful exploitation…
