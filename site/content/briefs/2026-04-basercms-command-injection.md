---
title: baserCMS OS Command Injection Vulnerability (CVE-2026-21861)
slug: 2026-04-basercms-command-injection
description: baserCMS versions prior to 5.2.3 are vulnerable to OS command injection, allowing an authenticated administrator to execute arbitrary commands on the server via maliciously crafted input to the core update functionality.
date: "2026-03-31T01:19:59Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-21861
  - command-injection
  - webserver
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-21861
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21861
  - https://basercms.net/security/JVN_20837860
  - https://github.com/baserproject/basercms/releases/tag/5.2.3
  - https://github.com/baserproject/basercms/security/advisories/GHSA-qxmc-6f24-g86g
rules:
  - title: baserCMS Command Injection Attempt via URI
    description: Detects potential command injection attempts in baserCMS through suspicious URI parameters containing shell commands.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: baserCMS Suspicious Process Execution from Web Server
    description: Detects suspicious processes spawned by the web server process which might indicate command injection.
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

baserCMS, a website development framework, is susceptible to an OS command injection vulnerability (CVE-2026-21861) in versions prior to 5.2.3. This flaw resides within the core update functionality, where user-controlled input is directly passed to the `exec()` function without proper sanitization or validation. A successful exploit allows an authenticated administrator to execute arbitrary operating system commands on the underlying server. The vulnerability was reported on March 30, 2026…
