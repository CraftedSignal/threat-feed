---
title: DefaultFuction CMS 1.0 Command Injection Vulnerability (CVE-2026-5333)
slug: 2026-04-defaultfunction-cms-command-injection
description: DefaultFuction Content-Management-System 1.0 is vulnerable to command injection via manipulation of the 'host' argument in the /admin/tools.php file, allowing remote attackers to execute arbitrary commands.
date: "2026-04-02T14:16:36Z"
severities:
  - high
tags:
  - command-injection
  - web-application
  - cve-2026-5333
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5333
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5333
  - https://vuldb.com/vuln/354667
rules:
  - title: Detect Suspicious HTTP Request to admin/tools.php
    description: Detects potential command injection attempts by monitoring HTTP requests to the /admin/tools.php endpoint with suspicious parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect Command Execution via Web Server Process
    description: Detects command execution originating from a web server process, potentially indicating command injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On April 2, 2026, a command injection vulnerability, CVE-2026-5333, was disclosed in DefaultFuction Content-Management-System version 1.0. The vulnerability resides in the `/admin/tools.php` file and is triggered by manipulating the `host` argument. This allows remote attackers to inject and execute arbitrary commands on the system. The existence of a public exploit increases the risk of exploitation, making it crucial for organizations using this CMS version to implement mitigation measures…
