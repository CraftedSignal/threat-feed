---
title: Totolink A8000RU Remote Command Injection Vulnerability
slug: 2026-04-totolink-rce
description: CVE-2026-7203 is a remote command injection vulnerability in the Totolink A8000RU router (version 7.1cu.643_b20200521) that allows an attacker to execute arbitrary commands on the device via manipulation of the 'enable' argument in the setUrlFilterRules function.
date: "2026-04-28T01:16:01Z"
severities:
  - critical
tags:
  - cve-2026-7203
  - rce
  - command-injection
  - totolink
vendors:
  - Totolink
products:
  - A8000RU
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
cves:
  - id: CVE-2026-7203
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7203
rules:
  - title: Detect Totolink RCE via CGI
    description: Detects command injection attempts on Totolink routers by monitoring requests to cstecgi.cgi with suspicious arguments.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - webserver
      - linux
rules_count: 1
---

CVE-2026-7203 is a critical vulnerability affecting Totolink A8000RU routers, specifically version 7.1cu.643_b20200521. The vulnerability resides in the CGI handler component, within the `setUrlFilterRules` function located in the `/cgi-bin/cstecgi.cgi` file. By manipulating the `enable` argument, a remote attacker can inject and execute arbitrary operating system commands on the affected device. This exploit is publicly available, increasing the risk of widespread exploitation. Successful…
