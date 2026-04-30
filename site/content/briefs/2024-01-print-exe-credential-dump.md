---
title: Print.exe Used to Dump Sensitive Files for Credential Access
slug: 2024-01-print-exe-credential-dump
description: Attackers are abusing the legitimate Windows Print.exe utility to copy sensitive files like NTDS.DIT and SAM in order to extract credentials, enabling local or remote credential access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-dumping
  - credential-access
  - windows
  - print.exe
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
references:
  - https://www.microsoft.com/en-us/security/blog/2026/02/06/active-exploitation-solarwinds-web-help-desk/
  - https://www.huntress.com/blog/credential-theft-expanding-your-reach-pt-2
  - https://lolbas-project.github.io/lolbas/Binaries/Print/
rules:
  - title: Sensitive File Dump Via Print.EXE
    description: Detects the abuse of the Print.exe utility for credential harvesting by copying sensitive files.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-evasion
    techniques:
      - T1003.002
      - T1003.003
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Print.exe Executed from Suspicious Location
    description: Detects Print.exe execution from unusual directories, indicating potential misuse.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are leveraging the `Print.exe` utility, a legitimate Windows command-line tool, to dump sensitive operating system files for credential harvesting. This technique involves using `Print.exe` to copy files like `ntds.dit`, `SAM`, `SECURITY`, and `SYSTEM` from their protected Windows directories. These files contain sensitive credential data that can be extracted offline. This activity was observed in relation to the SolarWinds Web Help Desk exploitation in early 2026. Abuse of `Print.exe` allows attackers to bypass traditional security measures that focus on blocking known malicious executables. This poses a significant risk because the extracted credentials can be used for lateral movement, privilege escalation, and data exfiltration.

## Attack Chain

1.  The attacker gains initial access to a Windows system, potentially through exploitation of a vulnerability in a web application or via compromised credentials.
2.  The attacker executes `print.exe` with command-line arguments specifying the source file to copy (e.g., `\config\SAM`, `\windows\ntds\ntds.dit`) and the destination path. The `/D` flag is used to designate the destination printer or file.
3.  `Print.exe` copies the targeted sensitive file (e.g., NTDS.DIT, SAM, SECURITY, SYSTEM) from its protected location.
4.  The copied file is typically saved to a location accessible to the attacker, either locally or on a network share.
5.  The attacker uses credential harvesting tools (e.g., `secretsdump.py` from Impacket) to extract user credentials (hashes) from the dumped files.
6.  The attacker cracks the password hashes or uses them directly for pass-the-hash attacks.
7.  Using the harvested credentials, the attacker moves laterally to other systems within the network, escalating privileges as needed.
8.  The attacker achieves their final objective, such as data exfiltration, deployment of ransomware, or other malicious activities.

## Impact

Successful exploitation allows attackers to steal domain or local account credentials. These stolen credentials enable unauthorized access to sensitive resources, including critical systems and data. The impact can range from data breaches and financial loss to complete compromise of the affected organization's network. While the scale of past attacks is not stated in the source, similar credential dumping attacks have led to breaches affecting millions of users.

## Recommendation

*   Deploy the Sigma rule `Sensitive File Dump Via Print.EXE` to detect abuse of `Print.exe` for copying sensitive files (logsource: `process_creation`).
*   Monitor process creation events for the execution of `print.exe` with command-line parameters that include sensitive file paths such as `\config\SAM`, `\config\SECURITY`, `\config\SYSTEM`, or `\windows\ntds\ntds.dit` (logsource: `process_creation`).
*   Implement access controls to restrict access to sensitive files like `ntds.dit`, `SAM`, `SECURITY`, and `SYSTEM` to only authorized accounts and processes.
*   Investigate any instances of `print.exe` copying files from the `\config` or `\windows\ntds` directories.
