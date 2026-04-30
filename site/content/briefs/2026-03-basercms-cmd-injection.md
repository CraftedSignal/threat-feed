---
title: baserCMS OS Command Injection Vulnerability (CVE-2026-30877)
slug: 2026-03-basercms-cmd-injection
description: baserCMS prior to version 5.2.3 contains an OS command injection vulnerability in the update functionality, allowing authenticated administrators to execute arbitrary OS commands on the server.
date: "2026-03-31T01:16:35Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - basercms
  - command-injection
  - webserver
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-30877
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-30877
  - https://basercms.net/security/JVN_20837860
  - https://github.com/baserproject/basercms/releases/tag/5.2.3
  - https://github.com/baserproject/basercms/security/advisories/GHSA-m9g7-rgfc-jcm7
rules:
  - title: baserCMS Update Command Injection Attempt
    description: Detects potential OS command injection attempts via HTTP requests to the baserCMS update functionality.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: baserCMS Suspicious Process Execution from Webserver
    description: Detects potential command injection exploitation in baserCMS by monitoring for unusual processes spawned by the web server.
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

baserCMS is a website development framework. Prior to version 5.2.3, a critical OS command injection vulnerability exists within the update functionality. This flaw allows an attacker, authenticated as an administrator, to inject and execute arbitrary operating system commands on the server hosting baserCMS. The commands are executed with the privileges of the user account running the baserCMS application, potentially leading to complete system compromise. This vulnerability was reported on…
