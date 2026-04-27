---
title: D-Link DIR-882 Remote Command Injection Vulnerability (CVE-2026-5844)
slug: 2026-04-dlink-command-injection
description: A command injection vulnerability (CVE-2026-5844) exists in the D-Link DIR-882 router version 1.01B02, allowing a remote attacker to execute arbitrary OS commands by manipulating the IPAddress argument in the HNAP1 SetNetworkSettings Handler via the prog.cgi script.
date: "2026-04-09T05:16:06Z"
severities:
  - critical
tags:
  - command-injection
  - d-link
  - router
  - cve-2026-5844
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5844
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5844
  - https://files.catbox.moe/ei31k1.zip
  - https://vuldb.com/vuln/356329
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect D-Link DIR-882 Command Injection Attempt
    description: Detects potential command injection attempts targeting the D-Link DIR-882 router via the prog.cgi script by looking for shell metacharacters in the IPAddress parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: D-Link DIR-882 Suspicious POST Request to prog.cgi
    description: Detects suspicious POST requests to prog.cgi, which may indicate exploitation attempts against D-Link DIR-882 routers.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5844 describes a critical command injection vulnerability affecting D-Link DIR-882 routers running firmware version 1.01B02. The vulnerability resides in the `sprintf` function within the `prog.cgi` script, specifically within the HNAP1 SetNetworkSettings Handler. A remote, unauthenticated attacker can exploit this flaw by manipulating the `IPAddress` argument, injecting arbitrary OS commands that are then executed with elevated privileges. The vulnerability is considered critical due…
