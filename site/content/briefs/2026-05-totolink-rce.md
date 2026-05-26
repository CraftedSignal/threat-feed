---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-9477)
slug: 2026-05-totolink-rce
description: A remote attacker can perform OS command injection on Totolink A8000RU routers by manipulating the 'mac' argument in the setAccessDeviceCfg function, affecting the device's web management interface.
date: "2026-05-26T14:04:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command injection
  - router
  - cve-2026-9477
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9477
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9477
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_349/README.md
  - https://vuldb.com/submit/813460
  - https://vuldb.com/vuln/365458
  - https://vuldb.com/vuln/365458/cti
  - https://www.totolink.net/
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt
    description: Detects CVE-2026-9477 exploitation — HTTP POST requests to /cgi-bin/cstecgi.cgi with shell metacharacters in the mac parameter indicating command injection attempt
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Totolink setAccessDeviceCfg Command Injection - Process Creation
    description: Detects potential exploitation of CVE-2026-9477 by monitoring for suspicious process creation originating from web server processes after a POST request to the affected endpoint.
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

A critical security vulnerability, CVE-2026-9477, has been identified in Totolink A8000RU router firmware version 7.1cu.643_b20200521. This flaw resides within the Web Management Interface, specifically in the `setAccessDeviceCfg` function located in `/cgi-bin/cstecgi.cgi`. A remote attacker can exploit this vulnerability by manipulating the `mac` argument, leading to arbitrary OS command injection. Public exploits are available, increasing the risk of widespread exploitation. This vulnerability allows attackers to execute unauthorized commands on the router, potentially leading to full system compromise, data theft, or denial of service.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A8000RU router with firmware version 7.1cu.643_b20200521.
2.  The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The request targets the `setAccessDeviceCfg` function.
4.  The attacker injects malicious OS commands within the `mac` argument of the HTTP request.
5.  The web server processes the request without proper sanitization of the `mac` argument.
6.  The injected OS commands are executed by the underlying operating system with elevated privileges.
7.  The attacker gains arbitrary code execution on the router.
8.  The attacker can then use this access to modify router settings, install malware, or pivot to other devices on the network.

## Impact

Successful exploitation of CVE-2026-9477 allows a remote attacker to execute arbitrary commands on the affected Totolink A8000RU router. This can lead to complete compromise of the device, including modification of settings, installation of malicious software, and potential use of the router as a botnet node. Given the widespread use of Totolink routers, a large number of devices are potentially vulnerable. A successful attack could lead to data breaches, service disruptions, and further lateral movement within the network.

## Recommendation

*   Apply available firmware updates from Totolink to patch CVE-2026-9477 as soon as possible.
*   Deploy the Sigma rule `Detect Totolink A8000RU Command Injection Attempt` to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with shell metacharacters in the `mac` argument.
*   Implement network segmentation to limit the impact of a compromised router on other network devices.
