---
title: WSASS Tool Execution for LSASS Memory Dumping
slug: 2024-01-wsass-execution
description: The WSASS tool is executed to dump LSASS memory, leveraging WER's WerFaultSecure.EXE to bypass Protected Process Light (PPL) protections, potentially leading to credential access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - lsass
  - memory-dumping
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/TwoSevenOneT/WSASS
  - https://www.zerosalarium.com/2025/09/Dumping-LSASS-With-WER-On-Modern-Windows-11.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_hktl_wsass.yml
rules:
  - title: WSASS Execution via Image Name
    description: Detects execution of WSASS based on the image name.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: WSASS Execution via CommandLine and WerFaultSecure
    description: Detects execution of WSASS based on command line arguments including WERFaultSecure.exe.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: WSASS Execution via Imphash
    description: Detects execution of WSASS based on the Imphash.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

WSASS is a tool used to dump LSASS (Local Security Authority Subsystem Service) memory on Windows systems. This tool leverages the Windows Error Reporting (WER) mechanism, specifically the `WerFaultSecure.exe` process, to bypass Protected Process Light (PPL) protections. By injecting into `WerFaultSecure.exe`, WSASS can access and dump the contents of LSASS, which often contains sensitive information such as passwords and credentials. The tool's goal is to circumvent standard security measures designed to prevent unauthorized access to LSASS memory. Defenders should monitor for the execution of WSASS and its interaction with `WerFaultSecure.exe` to detect potential credential theft attempts. The tool and technique were publicized around 2025, and the referenced Sigma rule was published in 2026.

## Attack Chain

1.  An attacker gains initial access to the target system (details not specified in source).
2.  The attacker deploys the WSASS tool to the compromised system.
3.  The attacker executes WSASS with the path to `WerFaultSecure.exe` and the LSASS process ID as command-line arguments (e.g., `wsass.exe "path to werfaultsecure" lsass_pid`).
4.  WSASS leverages WER's `WerFaultSecure.exe` to bypass PPL protections.
5.  `WerFaultSecure.exe` is used to gain access to the LSASS process memory.
6.  WSASS dumps the LSASS memory contents to a file or other storage location.
7.  The attacker retrieves the dumped LSASS memory file.
8.  The attacker parses the dumped LSASS memory for credentials and other sensitive information.

## Impact

Successful execution of WSASS and subsequent LSASS memory dumping can lead to the theft of sensitive credentials, including user passwords, Kerberos tickets, and NTLM hashes. This can allow attackers to move laterally within the network, escalate privileges, and gain access to critical systems and data. The impact can range from data breaches and financial loss to reputational damage and disruption of services. Organizations across all sectors that rely on Windows systems are potentially vulnerable.

## Recommendation

*   Deploy the Sigma rule `HackTool - WSASS Execution` to your SIEM and tune it for your environment to detect the execution of WSASS based on image name, hash, and command-line arguments.
*   Monitor process creation events for executions of `wsass.exe` using the `process_creation` log source.
*   Investigate any process execution where a process calls `WerFaultSecure.exe` with a PID as a command-line argument, especially if `wsass.exe` is involved, to identify potential credential access attempts.
