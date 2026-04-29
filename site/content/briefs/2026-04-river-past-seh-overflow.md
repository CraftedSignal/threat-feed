---
title: River Past Video Cleaner 7.6.3 SEH Buffer Overflow Vulnerability
slug: 2026-04-river-past-seh-overflow
description: River Past Video Cleaner 7.6.3 contains a structured exception handler buffer overflow vulnerability allowing local attackers to execute arbitrary code by providing a malicious string in the Lame_enc.dll field.
date: "2026-04-05T21:16:44Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2019-25670
  - buffer-overflow
  - seh-overflow
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploit System
cves:
  - id: CVE-2019-25670
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25670
  - https://www.exploit-db.com/exploits/46346
  - https://www.vulncheck.com/advisories/river-past-video-cleaner-buffer-overflow-via-seh
rules:
  - title: Suspicious Child Process of River Past Video Cleaner
    description: Detects suspicious child processes spawned by River Past Video Cleaner, indicating potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Registry Modification by River Past Video Cleaner
    description: Detects registry modifications made by River Past Video Cleaner, which could indicate malicious activity such as persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

River Past Video Cleaner version 7.6.3 is vulnerable to a structured exception handler (SEH) buffer overflow. This vulnerability allows a local attacker to execute arbitrary code on a vulnerable system. The attack involves crafting a malicious input string specifically designed to exploit the way the application handles exceptions related to the Lame_enc.dll library. This vulnerability can be exploited by an unauthenticated, local attacker. A successful exploit results in arbitrary code execution in the context of the application. Defenders should implement detection measures to identify malicious processes spawned by River Past Video Cleaner, or unexpected registry modifications.

## Attack Chain

1. A local attacker crafts a malicious input file designed to trigger the buffer overflow.
2. The attacker places the crafted malicious file in a location accessible to River Past Video Cleaner.
3. The attacker executes River Past Video Cleaner and instructs it to process the malicious file.
4. River Past Video Cleaner attempts to load or process the Lame_enc.dll library.
5. Due to the malicious input, a buffer overflow occurs within the structured exception handler of Lame_enc.dll. This overflow overwrites the saved SEH record on the stack.
6. When an exception is triggered (as a result of the overflow), the overwritten SEH record is used.
7. The overwritten SEH record redirects execution to attacker-controlled shellcode.
8. The attacker's shellcode executes, potentially granting the attacker arbitrary code execution within the context of the River Past Video Cleaner process.

## Impact

Successful exploitation of this vulnerability allows a local attacker to execute arbitrary code on the victim's machine. This could lead to complete system compromise, data theft, or installation of malware. The vulnerability is specific to River Past Video Cleaner 7.6.3. While specific victim counts are unavailable, the potential impact on any system running the vulnerable software is significant.

## Recommendation

*   Monitor process creations where the parent process is `RiverPastVideoCleaner.exe`, and the child process is unusual or suspicious (e.g., `cmd.exe`, `powershell.exe`) using process creation logs (logsource: process_creation). Deploy the Sigma rule provided to detect potentially malicious child processes.
*   Implement application control policies to prevent the execution of unsigned or untrusted executables in directories associated with River Past Video Cleaner.
*   Monitor for unexpected registry modifications performed by `RiverPastVideoCleaner.exe` (logsource: registry_set). The provided Sigma rule detects potentially malicious registry modifications.
