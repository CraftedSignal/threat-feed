---
title: Windows Win32K Untrusted Pointer Dereference Vulnerability (CVE-2026-32222)
slug: 2026-04-win32k-privesc
description: CVE-2026-32222 is an untrusted pointer dereference vulnerability in the Windows Win32K ICOMP component, allowing a local attacker to escalate privileges.
date: "2026-04-14T18:46:15Z"
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - cve-2026-32222
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32222
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32222
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32222
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Win32K ICOMP Calls
    description: Detects potentially malicious calls to the Win32K ICOMP component, indicative of CVE-2026-32222 exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential Kernel Memory Overwrite via Registry
    description: Detects registry modifications potentially related to kernel memory manipulation, a common technique used in privilege escalation attacks.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

CVE-2026-32222 describes an untrusted pointer dereference vulnerability residing within the Win32K ICOMP component of the Windows operating system. The vulnerability enables a locally authenticated attacker to escalate their privileges. According to the NVD, this vulnerability was published on April 14, 2026. The vulnerability exists because of how Win32K handles specific input when processing ICOMP calls. Exploitation requires an attacker to execute code locally on a vulnerable system…
