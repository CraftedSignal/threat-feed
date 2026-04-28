---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-5993)
slug: 2026-04-totolink-command-injection
description: A remote attacker can execute arbitrary OS commands on vulnerable Totolink A7100RU routers (version 7.4cu.2313_b20191024) by exploiting an OS command injection vulnerability in the setWiFiGuestCfg function via the wifiOff argument, potentially leading to full device compromise.
date: "2026-04-10T01:16:41Z"
severities:
  - critical
tags:
  - cve
  - command injection
  - totolink
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5993
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5993
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_165/README.md
  - https://vuldb.com/vuln/356547
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects potential command injection attempts targeting the Totolink A7100RU cstecgi.cgi script
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Shell Characters in Totolink WiFi Guest Config
    description: Detects shell metacharacters in the wifiOff parameter of the setWiFiGuestCfg function, indicative of command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5993 is a critical OS command injection vulnerability affecting Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability exists within the CGI handler, specifically in the `/cgi-bin/cstecgi.cgi` script's `setWiFiGuestCfg` function. By manipulating the `wifiOff` argument, an unauthenticated remote attacker can inject and execute arbitrary OS commands on the device. Publicly available exploits exist, increasing the risk of widespread exploitation. Successful exploitation grants the attacker complete control over the router, potentially enabling them to intercept network traffic, modify DNS settings, or use the device as part of a botnet.

## Attack Chain

1.  An attacker identifies a vulnerable Totolink A7100RU router running firmware version 7.4cu.2313_b20191024.
2.  The attacker sends a malicious HTTP request to `/cgi-bin/cstecgi.cgi`, targeting the `setWiFiGuestCfg` function.
3.  The HTTP request includes a crafted `wifiOff` argument containing an OS command injection payload.
4.  The `cstecgi.cgi` script processes the request without proper sanitization of the `wifiOff` argument.
5.  The injected OS command is executed with the privileges of the web server process.
6.  The attacker gains remote code execution on the router's operating system.
7.  The attacker may then install persistent backdoors, modify router configurations, or use the compromised router for further attacks.

## Impact

Successful exploitation of CVE-2026-5993 allows a remote attacker to execute arbitrary OS commands on the affected Totolink A7100RU router. This can lead to complete compromise of the device, potentially enabling attackers to intercept network traffic, modify DNS settings, create a botnet, or pivot to internal network resources. Given the publicly available exploits, a large number of devices could be vulnerable, leading to widespread network disruptions and security breaches.

## Recommendation

*   Deploy the Sigma rule `Detect Totolink A7100RU Command Injection Attempt` to your SIEM to identify malicious requests targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` containing command injection attempts in the `wifiOff` parameter.
*   Consider using a web application firewall (WAF) to filter out requests with potentially malicious payloads targeting the `wifiOff` parameter.
*   If possible, upgrade to a patched firmware version that addresses CVE-2026-5993. However, no such patch currently exists, so prioritize detection and mitigation.
