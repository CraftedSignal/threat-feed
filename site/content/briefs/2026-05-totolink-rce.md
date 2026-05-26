---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-9432)
slug: 2026-05-totolink-rce
description: A command injection vulnerability (CVE-2026-9432) exists in the setWiFiAdvancedCfg function of the /cgi-bin/cstecgi.cgi file within the Web Management Interface component of Totolink A8000RU 7.1cu.643_b20200521, allowing remote attackers to execute arbitrary OS commands by manipulating the bgProtection argument.
date: "2026-05-26T13:59:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - command injection
  - rce
  - totolink
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-9432
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9432
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_353/README.md
  - https://vuldb.com/submit/813905
  - https://vuldb.com/vuln/365413
  - https://vuldb.com/vuln/365413/cti
  - https://www.totolink.net/
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt (CVE-2026-9432)
    description: Detects CVE-2026-9432 exploitation attempt — HTTP POST request to /cgi-bin/cstecgi.cgi with shell metacharacters in the bgProtection parameter, indicating a command injection attempt targeting Totolink A8000RU routers.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect Totolink cstecgi.cgi Access
    description: Detects access to the cstecgi.cgi endpoint on Totolink routers, which may indicate attempts to exploit vulnerabilities like CVE-2026-9432.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - webserver
rules_count: 2
---

A critical command injection vulnerability, tracked as CVE-2026-9432, has been identified in Totolink A8000RU router firmware version 7.1cu.643_b20200521. The vulnerability resides within the web management interface, specifically in the `setWiFiAdvancedCfg` function located in `/cgi-bin/cstecgi.cgi`. By manipulating the `bgProtection` argument, a remote attacker can inject arbitrary OS commands. Publicly available exploit code increases the risk of widespread exploitation. This vulnerability poses a significant threat as it allows unauthorized remote access and control of affected devices.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A8000RU router with firmware version 7.1cu.643_b20200521 exposed to the internet.
2.  The attacker sends a crafted HTTP POST request to the `/cgi-bin/cstecgi.cgi` endpoint.
3.  Within the POST request, the attacker targets the `setWiFiAdvancedCfg` function.
4.  The attacker injects malicious OS commands into the `bgProtection` argument.
5.  The webserver processes the crafted request without proper sanitization.
6.  The injected OS commands are executed with the privileges of the webserver process.
7.  The attacker gains remote code execution on the router.
8.  The attacker could then use this access to modify router configurations, intercept network traffic, or pivot to other devices on the network.

## Impact

Successful exploitation of CVE-2026-9432 allows a remote attacker to execute arbitrary OS commands on the affected Totolink A8000RU device. This could lead to complete compromise of the router, including the ability to modify configurations, intercept network traffic, or use the device as a launchpad for further attacks against other devices on the network. Given the widespread use of these routers in home and small business environments, a large number of devices are potentially vulnerable.

## Recommendation

*   Apply available patches or firmware updates provided by Totolink to address CVE-2026-9432.
*   Deploy the Sigma rule "Detect Totolink A8000RU Command Injection Attempt (CVE-2026-9432)" to detect exploitation attempts against the web management interface.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with unusual characters or shell metacharacters in the `bgProtection` parameter (see rule).
*   Implement network segmentation to limit the impact of a compromised router on other network devices.
*   Disable remote access to the router's web management interface if not required to reduce attack surface.
