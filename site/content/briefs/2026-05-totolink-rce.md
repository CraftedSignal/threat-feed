---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-9435)
slug: 2026-05-totolink-rce
description: CVE-2026-9435 is an OS command injection vulnerability in the setQosCfg function of the Totolink A8000RU router's web management interface that allows remote attackers to execute arbitrary commands by manipulating the 'enable' argument.
date: "2026-05-26T14:02:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - router
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
  - id: CVE-2026-9435
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9435
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_356/README.md
  - https://vuldb.com/submit/813908
  - https://vuldb.com/vuln/365416
  - https://vuldb.com/vuln/365416/cti
  - https://www.totolink.net/
rules:
  - title: Detect Totolink A8000RU CVE-2026-9435 Exploitation Attempt
    description: Detects CVE-2026-9435 exploitation attempt - OS command injection via crafted request to /cgi-bin/cstecgi.cgi with shell metacharacters in the enable parameter
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect Totolink A8000RU CVE-2026-9435 Exploitation - POST Request
    description: Detects CVE-2026-9435 exploitation by identifying POST requests to the cstecgi.cgi endpoint with OS command injection attempts in the enable parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, CVE-2026-9435, has been identified in the Totolink A8000RU router, specifically version 7.1cu.643_b20200521. This flaw resides within the web management interface, affecting the `setQosCfg` function located in the `/cgi-bin/cstecgi.cgi` file. By manipulating the `enable` argument, an attacker can inject arbitrary OS commands. This vulnerability enables remote attackers, without prior authentication, to execute commands on the underlying operating system of the router. Given the public availability of exploit code, this vulnerability poses a significant risk, especially to home and small business networks utilizing the affected Totolink router model.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
2. The request targets the `setQosCfg` function.
3. The attacker manipulates the `enable` argument within the HTTP request.
4. The manipulated `enable` argument contains OS command injection payloads.
5. The `setQosCfg` function fails to properly sanitize the `enable` argument.
6. The unsanitized `enable` argument is passed to a system call, executing the injected OS command.
7. The attacker gains arbitrary code execution on the router's operating system.
8. The attacker can then perform further actions, such as modifying router configurations, establishing persistent access, or using the router as a pivot point to attack other devices on the network.

## Impact

Successful exploitation of CVE-2026-9435 allows an unauthenticated remote attacker to execute arbitrary commands on the affected Totolink A8000RU router. This could lead to a complete compromise of the device, enabling the attacker to reconfigure the device, steal sensitive information, or use it as a bot in a larger botnet. Given the potential for widespread exploitation due to the public availability of the exploit, a large number of Totolink A8000RU users are at risk.

## Recommendation

*   Apply any available firmware updates from Totolink to patch CVE-2026-9435.
*   Deploy the Sigma rule "Detect Totolink A8000RU CVE-2026-9435 Exploitation Attempt" to detect exploitation attempts in web server logs.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with unusual characters in the `enable` parameter, as covered by the Sigma rule.
*   Implement network segmentation to limit the impact of a compromised router on other devices on the network.
