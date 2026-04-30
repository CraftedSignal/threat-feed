---
title: LSA PPL Protection Setting Modification via CommandLine
slug: 2024-01-lsa-ppl-modification
description: Attackers modify LSA PPL protection settings via command-line tools like reg.exe and PowerShell to weaken system security and enable credential dumping.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
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

Attackers are increasingly targeting Local Security Authority (LSA) Protected Process Light (PPL) settings to disable this security mechanism, which protects sensitive processes like LSASS from unauthorized access. By modifying registry keys related to LSA PPL, attackers can weaken system defenses and facilitate credential dumping. This technique is often employed after gaining initial access to a system as a post-exploitation step. The use of command-line tools such as reg.exe, powershell.exe, and pwsh.exe for these modifications allows for automation and stealth. While the exact campaigns and threat actors using this are varied, the end goal remains the same: to bypass security controls and steal credentials.

## Attack Chain

1. Initial access is gained through unspecified means.
2. The attacker uses reg.exe, powershell.exe, or pwsh.exe to modify the registry.
3. The command line contains "ControlSet" and "\Control\Lsa" to target LSA settings.
4. Specific registry keys targeted include "IsPplAutoEnabled", "RunAsPPL", and "RunAsPPLBoot".
5. The attacker uses "Set-ItemProperty", "New-ItemProperty", or " add " to change registry values.
6. LSA PPL protection is disabled by modifying the targeted registry keys.
7. Credential dumping tools are deployed to extract credentials from LSASS memory.
8. Stolen credentials are used for lateral movement or privilege escalation.

## Impact

Successful modification of LSA PPL settings allows attackers to bypass a critical security control, making systems more vulnerable to credential theft. This can lead to widespread compromise within an organization, as stolen credentials can be used to access sensitive data, critical systems, and intellectual property. While the number of affected organizations is not specified, any Windows system relying on LSA PPL is potentially at risk.

## Recommendation

*   Deploy the Sigma rule "LSA PPL Protection Setting Modification via CommandLine" to your SIEM and tune for your environment to detect suspicious command-line activity targeting LSA PPL settings.
*   Enable Sysmon process-creation logging to activate the rule above.
*   Monitor for unexpected modifications to the registry keys "IsPplAutoEnabled", "RunAsPPL", and "RunAsPPLBoot" under the "ControlSet...\\Control\Lsa" path, which can indicate attempts to disable LSA PPL protection.
