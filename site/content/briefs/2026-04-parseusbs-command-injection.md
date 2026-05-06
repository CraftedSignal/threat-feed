---
title: parseusbs OS Command Injection Vulnerability (CVE-2026-40030)
slug: 2026-04-parseusbs-command-injection
description: parseusbs before 1.9 is vulnerable to OS command injection (CVE-2026-40030) due to improper sanitization of the volume listing path argument, potentially allowing arbitrary command execution via crafted volume paths.
date: "2026-04-08T22:16:23Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - command-injection
  - vulnerability
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40030
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40030
  - https://github.com/khyrenz/parseusbs/commit/99f05996494e7e41ea0c7e13145ba20eb793e46b
  - https://github.com/khyrenz/parseusbs/pull/10
  - https://mobasi.ai/sentinel
  - https://www.vulncheck.com/advisories/parseusbs-command-injection-via-volume-path-argument
rules:
  - title: Detect Suspicious Parseusbs Command Line Arguments
    description: Detects suspicious command line arguments passed to parseusbs that may indicate command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Usage of os.popen with Suspicious Arguments
    description: This rule detects usage of os.popen function within python scripts with shell metacharacters indicating potential code injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

parseusbs before version 1.9 is susceptible to an OS command injection vulnerability, identified as CVE-2026-40030. This flaw arises from the application's failure to sanitize the volume listing path argument (-v flag) before passing it to the `os.popen()` function in Python. This function executes shell commands, and in this case, uses `ls` to list volume contents. By crafting a malicious volume path containing shell metacharacters, an attacker can inject arbitrary commands that will be executed with the privileges of the parseusbs process. This vulnerability was reported by VulnCheck and patched in subsequent versions. Successful exploitation requires the attacker to control the `-v` flag's value, typically through command-line arguments.

## Attack Chain

1.  Attacker identifies a vulnerable parseusbs instance running a version prior to 1.9.
2.  The attacker crafts a malicious volume path argument containing shell metacharacters (e.g., `;/`).
3.  The attacker executes parseusbs with the `-v` flag, supplying the crafted volume path as the argument.  Example: `parseusbs -v "; command"`
4.  parseusbs passes the unsanitized volume path argument to the `os.popen()` function along with the `ls` command.
5.  The `os.popen()` function executes the combined command within a shell, injecting the attacker's commands.
6.  The injected commands are executed with the privileges of the parseusbs process.
7.  The attacker gains arbitrary command execution, potentially leading to system compromise.
8.  The attacker achieves persistence, lateral movement, or data exfiltration depending on the injected commands.

## Impact

Successful exploitation of CVE-2026-40030 allows an attacker to execute arbitrary commands on the system where parseusbs is running. This can lead to a full system compromise, including data theft, modification, or destruction. Given a CVSS v3.1 score of 7.8, this vulnerability is considered high severity. While specific victim counts and sectors are unknown, any system running a vulnerable version of parseusbs is at risk, particularly if the application processes user-supplied volume paths.

## Recommendation

*   Upgrade parseusbs to version 1.9 or later to remediate CVE-2026-40030 (Reference: Overview).
*   Deploy the Sigma rule `Detect Suspicious Parseusbs Command Line Arguments` to identify potential exploitation attempts (Reference: Rules).
*   Monitor command-line arguments passed to parseusbs for shell metacharacters (e.g., `;/|&`) (Reference: Attack Chain).
