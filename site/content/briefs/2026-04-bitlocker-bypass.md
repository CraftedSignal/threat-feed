---
title: Windows BitLocker Security Feature Bypass Vulnerability (CVE-2026-27913)
slug: 2026-04-bitlocker-bypass
description: CVE-2026-27913 describes an improper input validation vulnerability in Windows BitLocker that allows a local attacker to bypass security features.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - bitlocker
  - security-bypass
  - windows
  - cve-2026-27913
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2026-27913
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27913
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27913
ioc_counts:
  email: 1
rules:
  - title: Detect BitLocker Bypass via Modified Boot Configuration Data
    description: Detects potential BitLocker bypass attempts by monitoring changes to the Boot Configuration Data (BCD) store using bcdedit.exe.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential BitLocker Volume Unlock Bypass
    description: Detects potential BitLocker unlock bypass attempts by monitoring process creations that may be related to unlocking the volume without proper authentication.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-27913, discovered in April 2026, is a security vulnerability affecting Windows BitLocker. The vulnerability stems from improper input validation, which allows an unauthorized attacker with local access to bypass BitLocker security features. This could allow an attacker to gain unauthorized access to encrypted data or systems. The vulnerability is rated as HIGH severity with a CVSS v3.1 score of 7.7 (AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N). Exploitation of this vulnerability requires local…
