---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-5851)
slug: 2026-04-totolink-cmd-injection
description: A remote command injection vulnerability (CVE-2026-5851) exists in the Totolink A7100RU router version 7.4cu.2313_b20191024 via manipulation of the 'enable' argument in the setUPnPCfg function within the /cgi-bin/cstecgi.cgi CGI handler, potentially leading to arbitrary code execution.
date: "2026-04-09T06:16:23Z"
severities:
  - critical
tags:
  - cve-2026-5851
  - command-injection
  - totolink
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5851
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5851
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_157/README.md
  - https://vuldb.com/submit/791271
  - https://vuldb.com/vuln/356377
  - https://vuldb.com/vuln/356377/cti
  - https://www.totolink.net/
rules:
  - title: Detect Suspicious Totolink CGI Requests
    description: Detects requests to the cstecgi.cgi endpoint with suspicious parameters indicative of command injection attempts targeting CVE-2026-5851
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink Reboot Command
    description: Detects reboot commands executed by the webserver, potentially indicating exploitation of CVE-2026-5851
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

A critical security vulnerability, CVE-2026-5851, has been identified in the Totolink A7100RU router, specifically version 7.4cu.2313_b20191024. This flaw resides within the CGI handler component, affecting the `setUPnPCfg` function within the `/cgi-bin/cstecgi.cgi` file. The vulnerability allows for OS command injection through manipulation of the `enable` argument. Given that the exploit has been publicly released, it poses a significant risk to unpatched devices, potentially leading to…
