---
title: TOTOLINK X6000R Remote Command Injection Vulnerability
slug: 2026-03-totolink-rce
description: A remote command injection vulnerability exists in TOTOLINK X6000R routers, specifically versions 9.4.0cu.1360_B20241207 and 9.4.0cu.1498_B20250826, allowing attackers to execute arbitrary commands via manipulation of the Hostname argument in the setLanCfg function.
date: "2026-03-24T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - totolink
  - rce
  - command-injection
  - cve-2026-4611
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4611
  - https://vuldb.com/?ctiid.352475
  - https://vuldb.com/?id.352475
  - https://vuldb.com/?submit.775642
  - https://www.totolink.net/
rules:
  - title: Detect TOTOLINK X6000R Command Injection Attempt
    description: Detects attempts to exploit CVE-2026-4611 by identifying suspicious characters or command injection patterns in the Hostname parameter of requests to /usr/sbin/shttpd
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect TOTOLINK X6000R setLanCfg Access
    description: Detects access to the setLanCfg function in the shttpd webserver.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-4611, affects TOTOLINK X6000R routers running firmware versions 9.4.0cu.1360_B20241207 and 9.4.0cu.1498_B20250826. This vulnerability allows a remote attacker to inject operating system commands by manipulating the Hostname argument passed to the `setLanCfg` function within the `/usr/sbin/shttpd` binary. Successful exploitation grants the attacker the ability to execute arbitrary commands with elevated privileges on the router. Given the widespread deployment of these routers in home and small office networks, this vulnerability poses a significant risk of compromise, potentially leading to data theft, botnet recruitment, or denial-of-service attacks. The vulnerability was reported on March 23, 2026.

## Attack Chain

1.  Attacker identifies a vulnerable TOTOLINK X6000R router running firmware version 9.4.0cu.1360_B20241207 or 9.4.0cu.1498_B20250826.
2.  The attacker crafts a malicious HTTP request targeting the `/usr/sbin/shttpd` web server.
3.  The malicious request includes a modified `Hostname` argument within the `setLanCfg` function call.
4.  The `Hostname` argument contains OS command injection payloads such as backticks, semicolons, or command chaining operators (e.g., `&&`, `||`).
5.  The `shttpd` process, running with elevated privileges, processes the malicious `Hostname` argument without proper sanitization.
6.  The injected OS commands are executed by the system shell, leading to arbitrary code execution.
7.  The attacker gains control of the router's operating system.
8.  The attacker can then perform a variety of malicious actions, such as exfiltrating sensitive data, modifying router configurations, or using the router as a foothold for further network attacks.

## Impact

Successful exploitation of CVE-2026-4611 allows attackers to execute arbitrary commands on vulnerable TOTOLINK X6000R routers. This could lead to a complete compromise of the device, allowing attackers to steal sensitive information such as Wi-Fi passwords, intercept network traffic, or use the router as a launching point for attacks against other devices on the network. Given the potential for widespread exploitation, a large number of home and small business networks could be affected, resulting in significant financial and reputational damage.

## Recommendation

*   Monitor web server logs (category: `webserver`, product: `linux`) for requests containing suspicious characters or command injection attempts within the `Hostname` argument when accessing the `/usr/sbin/shttpd` endpoint.
*   Implement the provided Sigma rule to detect exploitation attempts in web server logs.
*   Contact TOTOLINK for a security patch or upgrade guidance.
*   Consider implementing network segmentation to limit the impact of a compromised router.
