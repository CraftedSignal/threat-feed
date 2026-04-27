---
title: Microsoft PowerShell Improper Input Validation Vulnerability (CVE-2026-26143)
slug: 2026-04-powershell-input-validation-bypass
description: An improper input validation vulnerability (CVE-2026-26143) in Microsoft PowerShell allows an unauthorized local attacker to bypass security features.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-26143
  - powershell
  - input-validation
  - bypass-uac
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
cves:
  - id: CVE-2026-26143
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26143
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26143
ioc_counts:
  email: 2
rules:
  - title: Detect Suspicious PowerShell Input Validation Bypass
    description: Detects potential attempts to bypass security features in PowerShell by exploiting input validation vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell with Suspicious Arguments
    description: Detects PowerShell processes that might be attempting to exploit CVE-2026-26143 by using uncommon arguments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-26143 describes a vulnerability in Microsoft PowerShell stemming from improper input validation. This flaw could allow a local, unauthorized attacker to bypass security features implemented within PowerShell. The vulnerability has a CVSS v3.1 score of 7.8, indicating a high severity. Successful exploitation could lead to significant compromise of the affected system. The vulnerability was reported to Microsoft and assigned CVE-2026-26143. Defenders should prioritize patching affected…
