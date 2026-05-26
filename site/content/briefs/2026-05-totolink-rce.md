---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-9386)
slug: 2026-05-totolink-rce
description: A remote attacker can execute arbitrary OS commands on a Totolink A8000RU router by injecting commands into the 'lang' argument of the setLanguageCfg function within the web management interface.
date: "2026-05-26T13:56:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - router
  - cve
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
  - id: CVE-2026-9386
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9386
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_333/README.md
  - https://vuldb.com/submit/813432
  - https://vuldb.com/vuln/365349
  - https://vuldb.com/vuln/365349/cti
  - https://www.totolink.net/
rules:
  - title: Detects CVE-2026-9386 Exploitation — Totolink A8000RU Command Injection
    description: Detects CVE-2026-9386 exploitation attempts by identifying suspicious requests to /cgi-bin/cstecgi.cgi with OS command injection payloads in the lang parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-9386 Exploitation Attempt - POST Request
    description: Detects CVE-2026-9386 exploitation attempts using POST requests with command injection in the lang parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-9386 describes a critical OS command injection vulnerability affecting Totolink A8000RU routers running firmware version 7.1cu.643_b20200521. The vulnerability resides in the `setLanguageCfg` function within the `/cgi-bin/cstecgi.cgi` file, which is part of the web management interface. An unauthenticated, remote attacker can exploit this vulnerability by injecting arbitrary OS commands into the `lang` argument. The attacker can then execute commands with elevated privileges on the device, potentially leading to complete system compromise. Publicly available exploit code exists, increasing the risk of widespread exploitation. This vulnerability poses a significant threat to home and small business networks using the affected Totolink router model.

## Attack Chain

1.  An attacker identifies a vulnerable Totolink A8000RU router exposed to the internet.
2.  The attacker sends a crafted HTTP request to `/cgi-bin/cstecgi.cgi`.
3.  The HTTP request targets the `setLanguageCfg` function.
4.  The request includes the `lang` argument with a malicious payload containing OS commands.
5.  The web server processes the request and passes the `lang` argument to the vulnerable function.
6.  The `setLanguageCfg` function fails to properly sanitize the input, allowing the injected OS commands to be executed.
7.  The injected OS commands are executed with the privileges of the web server process.
8.  The attacker gains remote code execution, allowing them to perform actions such as modifying system settings, installing malware, or establishing a persistent backdoor.

## Impact

Successful exploitation of CVE-2026-9386 allows a remote, unauthenticated attacker to execute arbitrary OS commands on the affected Totolink A8000RU router. This can lead to a complete compromise of the device, allowing the attacker to steal sensitive information, disrupt network services, or use the router as a jumping-off point for further attacks on the internal network. Given the publicly available exploit, widespread exploitation is possible, potentially affecting a large number of users.

## Recommendation

*   Apply available patches or firmware updates from Totolink to address CVE-2026-9386.
*   Monitor web server logs for suspicious requests targeting the `/cgi-bin/cstecgi.cgi` endpoint with unusual characters or commands in the `lang` parameter. Use the Sigma rule provided below to detect potential exploitation attempts.
*   Disable remote access to the router's web management interface to reduce the attack surface.
*   Implement network segmentation to limit the impact of a successful compromise.
*   Deploy the Sigma rule in this brief to your SIEM and tune for your environment.
