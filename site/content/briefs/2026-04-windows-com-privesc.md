---
title: Windows COM Privilege Escalation via CVE-2026-32162
slug: 2026-04-windows-com-privesc
description: CVE-2026-32162 allows an unauthorized attacker to achieve local privilege escalation in Windows COM by exploiting the acceptance of extraneous untrusted data with trusted data.
date: "2026-04-14T18:17:18Z"
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - CVE-2026-32162
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32162
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32162
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32162
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Suspicious COM Object Instantiation
    description: Detects suspicious process creations involving COM object instantiation which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Unusual Child Process of COM Host
    description: Detects unusual child processes of COM host processes, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32162 is a critical vulnerability affecting Windows Component Object Model (COM). The vulnerability stems from the improper handling of untrusted data when combined with trusted data during COM object processing. An attacker can exploit this flaw to elevate their privileges on a local system. The vulnerability was published on April 14, 2026, and is documented in the Microsoft Security Response Center update guide. Successful exploitation grants an attacker higher-level access to the…
