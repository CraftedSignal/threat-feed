---
title: Totolink A8000RU Remote Command Injection Vulnerability
slug: 2026-05-totolink-rce
description: A remote command injection vulnerability exists in the Totolink A8000RU router, specifically in the setAppFilterCfg function, allowing attackers to execute arbitrary commands by manipulating the 'enable' argument.
date: "2026-05-05T05:16:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
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
  - id: CVE-2026-7823
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7823
rules:
  - title: Detect Totolink RCE Attempt via setAppFilterCfg
    description: Detects potential remote command injection attempts targeting the setAppFilterCfg function in Totolink routers.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.002
    data_sources:
      - webserver
      - linux
  - title: Detect Common Command Injection Payloads in URI
    description: Detects common command injection payloads within URI parameters, which may indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security flaw, CVE-2026-7823, has been identified in the Totolink A8000RU router, version 7.1cu.643_b20200521. The vulnerability resides within the `setAppFilterCfg` function located in the `/cgi-bin/cstecgi.cgi` file. An attacker can exploit this vulnerability by remotely manipulating the `enable` argument, leading to arbitrary OS command injection. This exploit is publicly available, increasing the risk of widespread exploitation. Successful exploitation grants the attacker the ability to execute commands with elevated privileges on the affected device, potentially leading to full system compromise. The vulnerable device is a widely used home router model.

## Attack Chain

1. The attacker identifies a vulnerable Totolink A8000RU router exposed to the internet.
2. The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3. The request includes the `setAppFilterCfg` function call with a manipulated `enable` argument containing an OS command injection payload.
4. The router processes the request without proper input validation.
5. The injected OS command is executed by the router's operating system.
6. The attacker gains remote code execution on the router.
7. The attacker can then use the compromised router as a pivot point to attack other devices on the network or establish a persistent backdoor.
8. The attacker can exfiltrate sensitive data or disrupt network services.

## Impact

Successful exploitation of CVE-2026-7823 allows a remote attacker to execute arbitrary commands on the affected Totolink A8000RU router. This can lead to complete compromise of the device, including the ability to modify router settings, intercept network traffic, or use the router as a bot in a botnet. Given the widespread use of Totolink routers, a large number of devices are potentially vulnerable, making this a high-impact security issue.

## Recommendation

*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` containing suspicious characters or command injection attempts in the `enable` parameter (see Sigma rule: "Detect Totolink RCE Attempt via setAppFilterCfg").
*   Apply any available firmware updates from Totolink to patch CVE-2026-7823 when they become available.
*   Implement network segmentation to limit the impact of a compromised router on other devices on the network.
*   Deploy the Sigma rule "Detect Common Command Injection Payloads in URI" to identify generic command injection attempts against web applications.
