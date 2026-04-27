---
title: CVE-2026-32224 Use-After-Free in Windows Server Update Service
slug: 2024-01-02-wsus-privesc
description: CVE-2026-32224 is a use-after-free vulnerability in the Windows Server Update Service that allows a locally authenticated attacker to elevate privileges.
date: "2026-04-14T18:17:30Z"
severities:
  - high
tags:
  - cve-2026-32224
  - use-after-free
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32224
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32224
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32224
rules:
  - title: Detect Suspicious WSUS Process Creation
    description: Detects potential exploitation attempts of CVE-2026-32224 by monitoring process creation events related to WSUS with unusual parent processes.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect WSUS w3wp.exe spawning cmd.exe
    description: Detects potential exploitation attempts by detecting w3wp.exe (WSUS worker process) spawning cmd.exe, which is unusual.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32224 is a critical use-after-free vulnerability affecting the Windows Server Update Service (WSUS). Disclosed on April 14, 2026, this flaw allows an attacker with local access and valid credentials to potentially elevate their privileges on the affected system. The vulnerability resides within the core functionality of WSUS, which is responsible for managing and deploying updates to systems within a Windows environment. Successful exploitation could grant the attacker elevated…
