---
title: parseusbs Unsanitized LNK File Command Injection Vulnerability
slug: 2026-04-parseusbs-cmd-injection
description: parseusbs before 1.9 is vulnerable to OS command injection in parseUSBs.py due to unsanitized LNK file paths passed to os.popen(), allowing arbitrary command execution via crafted .lnk filenames.
date: "2026-04-08T22:16:23Z"
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

parseusbs before version 1.9 is susceptible to an OS command injection vulnerability (CVE-2026-40029) within the `parseUSBs.py` script. This flaw arises from the program's failure to sanitize LNK file paths before passing them to the `os.popen()` function. This allows an attacker to craft malicious .lnk filenames containing shell metacharacters. When `parseusbs` processes a USB drive containing such a file, the specially crafted filename is interpreted as a command, leading to arbitrary command…
