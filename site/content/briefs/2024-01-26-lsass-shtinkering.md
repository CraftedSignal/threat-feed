---
title: LSASS Credential Dumping via Windows Error Reporting (WER) Abuse
slug: 2024-01-26-lsass-shtinkering
description: Attackers can enable full user-mode dumps system-wide via registry modification to facilitate LSASS credential dumping, allowing extraction of credentials from process memory without deploying malware.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - lsass
  - wepw
vendors:
  - Microsoft
  - Elastic
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - Windows Error Reporting
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps
  - https://github.com/deepinstinct/Lsass-Shtinkering
  - https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf
rules:
  - title: Full User-Mode Dumps Enabled System-Wide
    description: Detects the enabling of full user-mode dumps system-wide via registry modification, a technique used to facilitate LSASS credential dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003.001
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: WER Dump File Creation
    description: Detects the creation of a WER dump file, which may indicate credential dumping activity.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The LSASS Shtinkering attack involves abusing Windows Error Reporting (WER) to dump the memory of the LSASS process, which contains sensitive credentials. By enabling full user-mode dumps system-wide, attackers can fake a crash on LSASS, causing WER to generate a dump file. This setting is not enabled by default and requires modifying the registry. The DeepInstinct researchers publicized this attack at Defcon 30, demonstrating a method to access credentials without directly injecting malware into the LSASS process. This technique allows attackers to bypass traditional endpoint detection mechanisms that focus on malware signatures, making it a stealthy approach to credential theft. Defenders should monitor for registry modifications related to WER dump settings to detect and prevent this attack.

## Attack Chain

1. The attacker gains initial access to the system, potentially through phishing or exploitation of a vulnerability.
2. The attacker modifies the registry key `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\DumpType` to the value `2` or `0x00000002` to enable full user-mode dumps system-wide.
3. The attacker triggers a crash or fakes a crash of the LSASS process.
4. Windows Error Reporting (WER) generates a full user-mode dump file of the LSASS process.
5. The dump file is stored in the location specified in the registry, typically `C:\ProgramData\Microsoft\Windows\WER\ReportQueue`.
6. The attacker accesses the generated dump file.
7. The attacker extracts credentials from the LSASS dump file using tools like Mimikatz or custom scripts.
8. The attacker uses the stolen credentials to move laterally within the network or access sensitive resources.

## Impact

Successful exploitation can lead to the compromise of domain credentials and other sensitive information stored in LSASS memory, such as NTLM hashes and Kerberos tickets. This can enable attackers to move laterally within the network, escalate privileges, and access critical systems and data. A single compromised system can lead to a widespread breach affecting numerous users and systems. The sectors most vulnerable are those handling sensitive data or critical infrastructure.

## Recommendation

*   Deploy the Sigma rule "Full User-Mode Dumps Enabled System-Wide" to your SIEM to detect suspicious registry modifications related to Windows Error Reporting (WER).
*   Examine process execution logs to identify any suspicious processes that may have triggered the dump, especially those not matching the legitimate `svchost.exe` process with user IDs `S-1-5-18`, `S-1-5-19`, or `S-1-5-20` as described in the rule's investigation guide.
*   Monitor for access to WER dump files located in `C:\ProgramData\Microsoft\Windows\WER\ReportQueue` using file monitoring rules.
*   Review and update endpoint protection configurations to ensure they can detect and block credential dumping techniques as mentioned in the rule's response and remediation steps.
