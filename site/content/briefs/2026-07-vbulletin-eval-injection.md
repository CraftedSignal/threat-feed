---
title: Critical Eval Injection Vulnerability in vBulletin Allows Remote Code Execution (CVE-2026-61511)
slug: 2026-07-vbulletin-eval-injection
description: An eval injection vulnerability, identified as CVE-2026-61511, exists in vBulletin versions 5.x through 5.7.5 and 6.x through 6.2.1, specifically within the vB5_Template_Runtime::runMaths() method, allowing unauthenticated remote attackers to achieve arbitrary PHP code execution by manipulating the pagenav[pagenumber] parameter through the unauthenticated ajax/render template route with phpfuck-style encoding.
date: "2026-07-27T14:19:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - remote-code-execution
  - eval-injection
  - php
  - unauthenticated
vendors:
  - vBulletin
products:
  - vBulletin 5.x through 5.7.5
  - vBulletin 6.x through 6.2.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: vBulletin 5.x through 5.7.5 and 6.x through 6.2.1 contains an eval injection vulnerability...that allows unauthenticated remote attackers to execute arbitrary PHP code by supplying crafted input through the pagenav[pagenumber] parameter.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allows unauthenticated remote attackers to execute arbitrary PHP code...by using phpfuck-style encoding with permitted characters to inject and execute arbitrary PHP code.
    confidence_band: high
cves:
  - id: CVE-2026-61511
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61511
rules:
  - title: Detects CVE-2026-61511 Exploitation - vBulletin Eval Injection
    description: Detects CVE-2026-61511 exploitation attempts against vBulletin by identifying malicious input in the pagenav[pagenumber] parameter via the unauthenticated ajax/render template route.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.006
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical eval injection vulnerability (CVE-2026-61511) has been discovered in vBulletin versions 5.x up to 5.7.5 and 6.x up to 6.2.1. This flaw resides within the `vB5_Template_Runtime::runMaths()` method of the template runtime engine. Unauthenticated remote attackers can leverage this vulnerability to execute arbitrary PHP code on affected vBulletin instances. The attack vector involves supplying specially crafted input through the `pagenav[pagenumber]` parameter via the unauthenticated `ajax/render` template route. Attackers can bypass existing regex filters designed to sanitize input by utilizing "phpfuck-style" encoding techniques, which use a limited set of characters to construct and execute complex PHP payloads. This vulnerability poses a severe risk as it allows for complete compromise of the vBulletin server without requiring any prior authentication, making it highly attractive to threat actors targeting forums and community platforms.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable vBulletin instance running versions 5.x up to 5.7.5 or 6.x up to 6.2.1.
2. The attacker crafts a malicious HTTP POST request targeting the `/ajax/render` template route of the vBulletin application.
3. The crafted request includes the `pagenav[pagenumber]` parameter, manipulated to contain a PHP payload obfuscated using "phpfuck-style encoding" or other command injection techniques.
4. The vBulletin application receives the request, and the `vB5_Template_Runtime::runMaths()` method attempts to process the value of the `pagenav[pagenumber]` parameter.
5. Due to the eval injection vulnerability and insufficient regex filtering, the application incorrectly evaluates the attacker's input as executable PHP code.
6. The injected PHP code then executes arbitrary system commands or functions provided by the attacker on the underlying server.
7. The attacker achieves unauthenticated remote code execution, gaining full control over the compromised vBulletin web server.

## Impact

A successful exploitation of CVE-2026-61511 grants unauthenticated remote code execution (RCE) on the affected vBulletin server. This can lead to complete compromise of the server, including data theft, defacement, installation of backdoors, deployment of web shells, or further network penetration. For forum owners, this means sensitive user data (usernames, email addresses, hashed passwords, private messages) can be exfiltrated. The integrity and availability of the vBulletin application can be severely degraded or destroyed. Given the widespread use of vBulletin for online communities, a large number of organizations globally are potentially at risk, though specific victim counts are not yet available.

## Recommendation

* Patch CVE-2026-61511 by updating vBulletin installations to a patched version beyond 5.7.5 or 6.2.1 immediately.
* Deploy the Sigma rule "Detects CVE-2026-61511 Exploitation - vBulletin Eval Injection" to your SIEM to detect exploitation attempts targeting the `ajax/render` endpoint.
* Enable comprehensive web server logging, including full request URLs, headers, and body content where possible, to ensure the `webserver` log source captures necessary details for detecting `cs-uri-stem` and `cs-uri-query` patterns.
