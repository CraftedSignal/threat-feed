---
title: Electerm Remote Code Execution Vulnerability via Malicious Filenames
slug: 2024-01-electerm-rce
description: A remote code execution vulnerability exists in Electerm versions 3.7.8 and earlier, where a malicious SSH server can inject arbitrary commands into a victim's system by crafting filenames with shell metacharacters that are executed when the user attempts to open or edit the file using the 'open with system editor' or 'edit with custom editor' feature.
date: "2026-05-08T18:43:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - electerm
  - sftp
  - remote code execution
vendors:
  - electerm
products:
  - electerm (<= 3.7.8)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-43943
    cvss: 7.8
references:
  - https://github.com/advisories/GHSA-q4p8-8j9m-8hxj
  - https://github.com/electerm/electerm
  - https://github.com/electerm/electerm/commit/24ce7103e264cffe6eb5476c0506a2379e6f8333
rules:
  - title: Detect Electerm RCE via Filename
    description: Detects CVE-2026-43943 exploitation — execution of shell commands within the Electerm application context due to unsanitized filenames.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation from Electerm
    description: Detects file creation in suspicious locations (e.g. /tmp) by Electerm following a potential RCE
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Electerm, a terminal/ssh/sftp client, is vulnerable to a remote code execution (RCE) attack (CVE-2026-43943) when using the "open with system editor" or "Edit with custom editor" feature. This vulnerability affects versions 3.7.8 and earlier. A malicious actor who controls the SSH server or has the ability to manipulate filenames can inject shell metacharacters into a filename. When a user attempts to open the file with the vulnerable feature, Electerm passes the filename directly to the command line without sanitization, leading to command execution with the user's privileges. This allows the attacker to potentially run arbitrary code, install malware, or move laterally within the network. The vulnerability was patched in version 3.7.9.

## Attack Chain

1.  Attacker compromises or sets up a malicious SSH server.
2.  Attacker creates a file with a specially crafted filename containing shell metacharacters (e.g., `evil; rm -rf /tmp; touch /tmp/pwned`).
3.  Victim connects to the malicious SSH server using Electerm.
4.  Victim browses the SFTP file system and sees the attacker-controlled filename.
5.  Victim selects the malicious file and chooses the "open with system editor" or "Edit with custom editor" option.
6.  Electerm executes a command to open the file, passing the malicious filename unsanitized to the system shell (e.g., `xdg-open "evil; rm -rf /tmp; touch /tmp/pwned"`).
7.  The shell executes the injected commands, deleting files in `/tmp` and creating a file named `/tmp/pwned` in this example.
8.  Attacker achieves arbitrary code execution on the victim's machine with the user's privileges.

## Impact

Successful exploitation of this vulnerability allows a malicious actor to execute arbitrary code on the victim's machine. This could lead to a variety of malicious outcomes, including malware installation, data theft, or lateral movement within the victim's network. The number of potential victims is limited to Electerm users who connect to untrusted SSH servers and use the vulnerable "open with system editor" or "Edit with custom editor" features. This vulnerability could have significant impact for developers and system administrators who rely on Electerm for remote server management.

## Recommendation

*   Upgrade Electerm to version 3.7.9 or later to patch CVE-2026-43943.
*   Deploy the Sigma rule `Detect Electerm RCE via Filename` to detect exploitation attempts.
*   Until a patch can be applied, refrain from using the "open with system editor" or "Edit with custom editor" feature when connected to untrusted SSH servers, as recommended in the advisory.
*   If the "open with system editor" feature must be used, ensure connections are exclusively established with trusted servers and perform rigorous filename validation before editing.
