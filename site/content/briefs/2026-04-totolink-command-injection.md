---
title: Totolink A8000RU OS Command Injection Vulnerability
slug: 2026-04-totolink-command-injection
description: A critical OS command injection vulnerability (CVE-2026-7153) exists in the Totolink A8000RU router, specifically in the `setMiniuiHomeInfoShow` function, allowing remote attackers to execute arbitrary commands by manipulating the `sys_info` argument.
date: "2026-04-27T20:32:04Z"
severities:
  - critical
tags:
  - cve-2026-7153
  - command injection
  - router
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-7153
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7153
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_317/README.md
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt
    description: Detects potential command injection attempts targeting the Totolink A8000RU router via the cstecgi.cgi endpoint by looking for common command injection payloads.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Exploitation of Totolink CVE-2026-7153
    description: Detects successful exploitation of the Totolink A8000RU router vulnerability (CVE-2026-7153) by monitoring for suspicious process creation events following requests to the vulnerable CGI endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical security vulnerability, identified as CVE-2026-7153, has been discovered in the Totolink A8000RU router, version 7.1cu.643_b20200521. This flaw resides within the CGI Handler component, specifically affecting the `setMiniuiHomeInfoShow` function located in the `/cgi-bin/cstecgi.cgi` file. By exploiting this vulnerability, a remote attacker can inject and execute arbitrary operating system commands on the affected device. Public exploits are available, increasing the risk of…
