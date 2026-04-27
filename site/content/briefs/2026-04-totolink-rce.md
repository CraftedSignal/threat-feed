---
title: Totolink A7100RU Remote Command Injection Vulnerability (CVE-2026-5995)
slug: 2026-04-totolink-rce
description: A remote command injection vulnerability (CVE-2026-5995) exists in the Totolink A7100RU router, specifically affecting the `setMiniuiHomeInfoShow` function within the `/cgi-bin/cstecgi.cgi` file, allowing unauthenticated attackers to execute arbitrary OS commands by manipulating the `lan_info` argument.
date: "2026-04-10T01:16:42Z"
severities:
  - critical
tags:
  - command-injection
  - router
  - cve-2026-5995
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5995
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5995
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_167/README.md
  - https://vuldb.com/vuln/356549
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects attempts to exploit the CVE-2026-5995 command injection vulnerability in Totolink A7100RU routers via suspicious lan_info parameters in requests to cstecgi.cgi.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Unauthorized Access Attempt
    description: Detects attempts to access cstecgi.cgi which should normally not be accessed by clients.
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

CVE-2026-5995 is a critical vulnerability affecting Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability resides within the `setMiniuiHomeInfoShow` function of the `/cgi-bin/cstecgi.cgi` file, a component of the CGI handler. Successful exploitation allows a remote attacker to inject and execute arbitrary OS commands on the device by manipulating the `lan_info` argument. This vulnerability poses a significant risk as it requires no authentication and has a…
