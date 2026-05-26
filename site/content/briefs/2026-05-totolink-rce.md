---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-9388)
slug: 2026-05-totolink-rce
description: Totolink A8000RU version 7.1cu.643_b20200521 contains an OS command injection vulnerability (CVE-2026-9388) in the Web Management Interface component, where manipulating the 'mode' argument in the setScheduleCfg function of the /cgi-bin/cstecgi.cgi file can lead to arbitrary command execution, and this vulnerability can be exploited remotely with a public exploit available.
date: "2026-05-26T13:57:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - command-injection
  - router
  - network-device
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
  - id: CVE-2026-9388
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9388
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_335/README.md
  - https://vuldb.com/submit/813434
  - https://vuldb.com/vuln/365351
  - https://vuldb.com/vuln/365351/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9388 Exploitation Attempt via Crafted HTTP Request
    description: Detects CVE-2026-9388 exploitation attempt — HTTP request to cstecgi.cgi with shell metacharacters in the mode parameter, indicating command injection attempt
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-9388 Exploitation Attempt via Suspicious User Agent
    description: Detects CVE-2026-9388 exploitation attempt — Attempts to exploit the vulnerability from User-Agents that do not conform to typical browser configurations.
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

CVE-2026-9388 is a critical OS command injection vulnerability affecting Totolink A8000RU router version 7.1cu.643_b20200521. The vulnerability resides in the Web Management Interface, specifically within the `setScheduleCfg` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `mode` argument, an attacker can inject arbitrary operating system commands. This vulnerability can be exploited remotely without authentication. A public exploit is available, increasing the likelihood of exploitation. Routers are a common target for botnet recruitment and data exfiltration.

## Attack Chain

1. An attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2. The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint, targeting the `setScheduleCfg` function.
3. The HTTP request includes a malicious payload in the `mode` argument, designed to inject OS commands.
4. The web server processes the request without proper sanitization of the `mode` argument.
5. The injected OS command is executed with the privileges of the web server process.
6. The attacker gains remote code execution on the router.
7. The attacker may install malware, change DNS settings, or use the router to pivot to other internal network devices.
8. The attacker compromises the router and can use it for malicious activities such as botnet participation, data exfiltration, or denial-of-service attacks.

## Impact

Successful exploitation of CVE-2026-9388 allows an unauthenticated attacker to execute arbitrary commands on the affected Totolink A8000RU router. This can lead to a complete compromise of the device, enabling attackers to steal sensitive information, use the router as part of a botnet, or disrupt network services. Given the availability of a public exploit, the risk of widespread exploitation is high.

## Recommendation

*   Apply the vendor-supplied patch or upgrade the firmware of the Totolink A8000RU router to a version that addresses CVE-2026-9388.
*   Deploy the Sigma rule "Detect CVE-2026-9388 Exploitation Attempt via Crafted HTTP Request" to detect malicious requests targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious activity related to the `/cgi-bin/cstecgi.cgi` endpoint.
*   Implement network segmentation to limit the impact of a compromised router on other network devices.
*   Enforce strong passwords for router administrative interfaces and disable remote administration if not required.
