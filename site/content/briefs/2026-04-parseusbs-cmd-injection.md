---
title: parseusbs Unsanitized LNK File Command Injection Vulnerability
slug: 2026-04-parseusbs-cmd-injection
description: parseusbs before 1.9 is vulnerable to OS command injection in parseUSBs.py due to unsanitized LNK file paths passed to os.popen(), allowing arbitrary command execution via crafted .lnk filenames.
date: "2026-04-08T22:16:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command injection
  - lnk
  - parseusbs
  - cve-2026-40029
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40029
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40029
  - https://github.com/khyrenz/parseusbs/commit/99f05996494e7e41ea0c7e13145ba20eb793e46b
  - https://github.com/khyrenz/parseusbs/pull/10
  - https://www.vulncheck.com/advisories/parseusbs-command-injection-via-crafted-lnk-filename
rules:
  - title: Detect Suspicious Process Creation by Python
    description: Detects suspicious processes spawned by python, which could indicate command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.002
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Creation of LNK Files in Removable Media
    description: Detects the creation of LNK files on removable media, which can be an indicator of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1020
    data_sources:
      - file_event
      - windows
rules_count: 2
---

parseusbs before version 1.9 is susceptible to an OS command injection vulnerability (CVE-2026-40029) within the `parseUSBs.py` script. This flaw arises from the program's failure to sanitize LNK file paths before passing them to the `os.popen()` function. This allows an attacker to craft malicious .lnk filenames containing shell metacharacters. When `parseusbs` processes a USB drive containing such a file, the specially crafted filename is interpreted as a command, leading to arbitrary command execution on the system of the forensic examiner using the tool. The vulnerable versions of parseusbs are used by security professionals for USB forensic analysis, making successful exploitation dangerous for those running the tool.

## Attack Chain

1. The attacker crafts a malicious .lnk file. The filename includes shell metacharacters designed to execute arbitrary commands. For example, a filename could be `test.lnk; rm -rf /tmp`.
2. The attacker places the crafted .lnk file onto a USB drive.
3. A forensic examiner uses parseusbs (version before 1.9) to analyze the USB drive.
4. The `parseUSBs.py` script processes the files on the USB drive, including the malicious .lnk file.
5. The script extracts the .lnk file path without proper sanitization.
6. The unsanitized .lnk file path is passed to the `os.popen()` function.
7. The `os.popen()` function interprets the shell metacharacters in the filename, executing the attacker's injected command.
8. The attacker achieves arbitrary code execution on the examiner's system, allowing them to potentially compromise the system, steal sensitive data, or further pivot into the network.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the system of a forensic examiner using `parseusbs`. This could lead to complete system compromise, data exfiltration, or further malicious activities. Given that `parseusbs` is a tool used by security professionals, a successful attack could have significant consequences, potentially exposing sensitive forensic data. The impact is particularly severe as the examiner likely has access to sensitive information related to their investigations.

## Recommendation

*   Upgrade `parseusbs` to version 1.9 or later to remediate CVE-2026-40029.
*   Monitor process creation events for unexpected processes spawned by Python (`python.exe` or `python3`). Use the Sigma rule "Detect Suspicious Process Creation by Python" to detect potential exploitation attempts.
*   Implement file integrity monitoring for LNK files, particularly those found on USB drives. The Sigma rule "Detect Creation of LNK Files in Removable Media" can help identify suspicious LNK file creation.
