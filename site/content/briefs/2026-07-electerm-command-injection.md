---
title: electerm has Command Injection in File System Operations (rmrf, mv, cp)
slug: 2026-07-electerm-command-injection
description: A command injection vulnerability, CVE-2026-49255, exists in electerm's file system operations (`rmrf`, `mv`, `cp`) due to improper sanitization of file paths containing shell metacharacters. An attacker can leverage this by presenting a malicious SSH/SFTP server with crafted filenames. When a victim performs file operations on these files, arbitrary commands can be executed on the victim's system as the electerm desktop user, potentially leading to data exfiltration, malware installation, or system compromise on both Windows and POSIX-based operating systems.
date: "2026-07-03T11:37:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - rce
  - client-side
  - application-vulnerability
  - electerm
vendors:
  - electerm
products:
  - electerm <= 3.11.0
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Shell metacharacters break out of the quoted argument and execute arbitrary commands.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Arbitrary command execution as the electerm desktop user ... malware installation
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Arbitrary command execution as the electerm desktop user ... system compromise
    confidence_band: med
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: Arbitrary command execution as the electerm desktop user ... system compromise
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
    evidence: Data exfiltration
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Data exfiltration
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: A command injection vulnerability exists in electerm's file system operations (`rmrf`, `mv`, `cp`)
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-v5ff-xmfp-p245
  - https://github.com/electerm/electerm/commit/aa778818843b9c083bd711cd04644d102fcb5a42
rules:
  - title: Detects CVE-2026-49255 Exploitation - electerm Command Injection PoC
    description: Detects exploitation of CVE-2026-49255 where electerm performs command injection, specifically using the 'touch /tmp/pwned' proof-of-concept payload observed in the advisory. This indicates arbitrary command execution on the victim's system.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical command injection vulnerability (CVE-2026-49255) has been identified in electerm, a popular terminal emulator and SSH/SFTP client, affecting versions up to and including 3.11.0. The flaw resides within the application's file system operations, specifically `rmrf()`, `mv()`, and `cp()`, which are implemented in `src/app/lib/fs.js`. These functions construct shell commands by directly embedding user-controlled file paths without proper escaping of shell metacharacters. Attackers can exploit this by setting up a malicious SSH/SFTP server that presents files with specially crafted names containing metacharacters like `"` or `'`. When a victim connects to such a server and performs file operations (such as remote-to-local transfers or renaming), the embedded shell metacharacters escape the intended argument, leading to arbitrary command execution on the victim's system under the context of the electerm user. This allows for potential data exfiltration, malware installation, or full system compromise on both Windows and POSIX (Linux/macOS) platforms.

## Attack Chain

1. An attacker sets up a malicious SSH/SFTP server or compromises an existing one, making it accessible to potential victims.
2. The attacker crafts filenames containing shell metacharacters (e.g., `file"$(touch /tmp/pwned)"`, `malicious';id;'file`) designed to break out of quoted arguments in shell commands.
3. A victim, using a vulnerable version of electerm, connects to the malicious SSH/SFTP server.
4. The victim initiates a file operation (e.g., remote-to-local transfer, move, copy, or a rename due to conflict) involving the attacker-controlled malicious filename.
5. electerm's vulnerable file system functions (`rmrf()`, `mv()`, or `cp()`) are invoked, attempting to process the malicious filename.
6. The functions construct an underlying shell command by interpolating the malicious filename directly into a command string, failing to properly escape the shell metacharacters.
7. The shell metacharacters (e.g., `"` or `'`) in the filename escape the intended argument, causing the embedded arbitrary commands to be executed by the underlying shell.
8. The injected arbitrary commands run with the privileges of the electerm desktop user, leading to arbitrary code execution, system compromise, or data exfiltration.

## Impact

Successful exploitation of CVE-2026-49255 results in arbitrary command execution on the victim's system. This allows attackers to perform actions with the same privileges as the electerm desktop user, which typically includes access to user files and configuration. The consequences can include data exfiltration, installation of additional malware, further system compromise, or even the establishment of persistence. Both POSIX-based operating systems (Linux, macOS) and Windows are affected, widening the potential target base. The severity is high due to the ease of exploitation via crafted filenames and the direct impact of arbitrary code execution.

## Recommendation

Prioritized, concrete actions for detection engineering teams.
*   Immediately upgrade electerm to a patched version (newer than 3.11.0) to remediate CVE-2026-49255.
*   Deploy the Sigma rule provided in this brief to detect anomalous process creation that may indicate exploitation attempts.
*   Educate users about the risks of connecting to untrusted SSH/SFTP servers and performing file operations with suspicious filenames, as highlighted in the "Attack Chain" section.
*   Implement strong egress filtering to block unexpected outbound connections from user workstations that could indicate command and control activity post-exploitation.
