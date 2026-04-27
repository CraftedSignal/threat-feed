---
title: parseusbs OS Command Injection Vulnerability (CVE-2026-40030)
slug: 2026-04-parseusbs-command-injection
description: parseusbs before 1.9 is vulnerable to OS command injection (CVE-2026-40030) due to improper sanitization of the volume listing path argument, potentially allowing arbitrary command execution via crafted volume paths.
date: "2026-04-08T22:16:23Z"
severities:
  - high
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
ioc_counts:
  email: 1
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

parseusbs before version 1.9 is susceptible to an OS command injection vulnerability, identified as CVE-2026-40030. This flaw arises from the application's failure to sanitize the volume listing path argument (-v flag) before passing it to the `os.popen()` function in Python. This function executes shell commands, and in this case, uses `ls` to list volume contents. By crafting a malicious volume path containing shell metacharacters, an attacker can inject arbitrary commands that will be…
