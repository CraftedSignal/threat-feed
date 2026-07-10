---
title: TinyCC Masquerading as Svchost for Shellcode Execution
slug: 2024-01-09-tinycc-shellcode
description: Attackers rename TinyCC (tcc.exe) to svchost.exe and use it to compile and execute C source files containing shellcode, using the `-nostdlib` and `-run` flags, as observed in the Lotus Blossom Chrysalis backdoor campaign, indicating potential evasion and malicious code execution.
date: "2024-01-09T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lotus Blossom
tags:
  - tinycc
  - shellcode
  - svchost
  - lotus-blossom
  - chrysalis
  - t1059.003
  - t1027
vendors:
  - TinyCC
products:
  - Tiny C Compiler
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1027/
  - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
  - https://github.com/phoenixthrush/Tiny-C-Compiler
rules:
  - title: Detect TinyCC Renamed and Executing Shellcode
    description: Detects TinyCC (tcc.exe) renamed to svchost.exe executing with shellcode compilation flags.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Suspicious TCC Execution from Non-Standard Path
    description: Detects TinyCC (tcc.exe) executing from a non-standard path with suspicious flags.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Lotus Blossom threat actor has been observed using a technique involving the Tiny C Compiler (TinyCC) to execute shellcode on compromised systems.  This technique involves renaming the legitimate `tcc.exe` binary to `svchost.exe` to masquerade as a legitimate Windows process. The renamed compiler is then used to compile and execute C source files containing malicious shellcode. A key aspect of this attack is the use of the `-nostdlib` and `-run` flags when invoking the renamed `tcc.exe`.  This behavior was specifically observed in the Chrysalis backdoor campaign, where the attackers executed `conf.c` containing Metasploit block_api shellcode.  This technique allows attackers to bypass traditional security measures by leveraging a legitimate tool in an unexpected way and from unusual locations. The ability of TinyCC to compile and execute code on-the-fly makes it an attractive tool for attackers seeking to evade detection.

## Attack Chain

1.  The attacker gains initial access to the system (details not specified in source).
2.  The attacker drops the Tiny C Compiler (tcc.exe) onto the compromised system, typically in a user-writable directory like AppData or Temp.
3.  The attacker renames `tcc.exe` to `svchost.exe` to masquerade as a legitimate Windows process. This helps evade detection based on process names.
4.  The attacker drops a C source file (e.g., `conf.c`) containing malicious shellcode onto the system.
5.  The attacker executes the renamed `svchost.exe` (originally tcc.exe) to compile and execute the C source file containing the shellcode. The command line includes the flags `-nostdlib` and `-run`.
6.  The shellcode executes, performing malicious actions such as establishing a reverse shell, downloading additional payloads, or injecting into other processes.
7.  The attacker uses the established foothold to move laterally within the network.
8.  The attacker achieves their final objective, which could include data exfiltration, deploying ransomware, or establishing persistent access.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the compromised system. This can lead to data theft, system compromise, and further propagation within the network.  The Lotus Blossom group has used this technique to install the Chrysalis backdoor. The number of victims and the sectors targeted by this specific campaign are not detailed in the provided source, but the technique is a significant threat to organizations due to its potential for stealth and impact.

## Recommendation

*   Enable Sysmon process-creation logging (Event ID 1) and ensure command-line arguments are captured, to enable the rules above.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Monitor for processes named `svchost.exe` that are not located in the standard Windows system directories (`C:\\Windows\\System32\\` or `C:\\Windows\\SysWOW64\\`), as these are indicative of the renamed TinyCC binary based on the provided data and the detection logic.
*   Investigate any `svchost.exe` or `tcc.exe` processes executing with the `-nostdlib` and `-run` flags, especially when compiling `.c` files, using the detection logic in the Sigma rule.
*   Implement application control policies to restrict the execution of binaries from user-writable directories, mitigating the initial execution of the renamed compiler.
