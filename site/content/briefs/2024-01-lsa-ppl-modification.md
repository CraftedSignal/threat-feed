---
title: LSA PPL Protection Setting Modification via CommandLine
slug: 2024-01-lsa-ppl-modification
description: Attackers modify LSA PPL protection settings via command-line tools like reg.exe and PowerShell to weaken system security and enable credential dumping.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - defense-evasion
  - credential-access
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/
  - https://github.com/shoober420/windows11-scripts/blob/38d83331738cd713ccb42f2c4557d17a27aefd98/Windows11Tweaks.bat#L1825
rules:
  - title: LSA PPL Protection Setting Modification via CommandLine
    description: Detects modification of LSA PPL protection settings via CommandLine, which may indicate an attempt to disable protection and enable credential dumping tools to access LSASS process memory.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1562.010
    data_sources:
      - process_creation
      - windows
  - title: LSA PPL Protection Setting Modification via pwsh.exe
    description: Detects modification of LSA PPL protection settings via pwsh.exe.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1562.010
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly targeting Local Security Authority (LSA) Protected Process Light (PPL) settings to disable this security mechanism, which protects sensitive processes like LSASS from unauthorized access. By modifying registry keys related to LSA PPL, attackers can weaken system defenses and facilitate credential dumping. This technique is often employed after gaining initial access to a system as a post-exploitation step. The use of command-line tools such as reg.exe, powershell.exe…
