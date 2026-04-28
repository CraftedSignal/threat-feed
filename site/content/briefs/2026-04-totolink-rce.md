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

CVE-2026-5995 is a critical vulnerability affecting Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability resides within the `setMiniuiHomeInfoShow` function of the `/cgi-bin/cstecgi.cgi` file, a component of the CGI handler. Successful exploitation allows a remote attacker to inject and execute arbitrary OS commands on the device by manipulating the `lan_info` argument. This vulnerability poses a significant risk as it requires no authentication and has a publicly available exploit, potentially enabling attackers to compromise vulnerable devices remotely. The scope of targeting includes any Totolink A7100RU router using the specified firmware version exposed to the internet or accessible from an attacker-controlled network.

## Attack Chain

1.  The attacker identifies a Totolink A7100RU router running firmware version 7.4cu.2313_b20191024.
2.  The attacker sends a crafted HTTP request to `/cgi-bin/cstecgi.cgi`.
3.  The request targets the `setMiniuiHomeInfoShow` function.
4.  The `lan_info` argument within the HTTP request is manipulated to include an OS command injection payload.
5.  The CGI handler processes the request and executes the injected OS command.
6.  The injected command executes with the privileges of the web server process.
7.  The attacker gains unauthorized access to the device's operating system.
8.  The attacker can then perform malicious activities such as gaining full system control, modifying router configurations, or using the device as part of a botnet.

## Impact

Successful exploitation of CVE-2026-5995 allows an unauthenticated remote attacker to execute arbitrary OS commands on the affected Totolink A7100RU router. This could lead to complete compromise of the device, potentially enabling attackers to steal sensitive information, modify router settings, or use the device as a launchpad for further attacks against internal networks. Given the widespread use of these routers, a large number of devices are potentially vulnerable. The impact could range from individual users experiencing service disruption to entire networks being compromised.

## Recommendation

*   Apply any available patches or firmware updates from Totolink to address CVE-2026-5995.
*   Monitor web server logs for suspicious requests targeting `/cgi-bin/cstecgi.cgi` with unusual `lan_info` parameters to detect potential exploitation attempts and deploy the Sigma rule `Detect Totolink A7100RU Command Injection Attempt`.
*   Implement network segmentation to limit the impact of a compromised router on other network devices.
*   Consider using a web application firewall (WAF) to filter out malicious requests targeting the `/cgi-bin/cstecgi.cgi` endpoint.
