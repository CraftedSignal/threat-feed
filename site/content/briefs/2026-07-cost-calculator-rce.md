---
title: Remote Code Execution in Cost Calculator Builder PRO WordPress Plugin
slug: 2026-07-cost-calculator-rce
description: The Cost Calculator Builder PRO plugin for WordPress, versions up to and including 4.0.3, is vulnerable to unauthenticated Remote Code Execution (RCE) via CVE-2026-14900 due to insufficient sanitization of the `orderDetails[*].originalValue` field, allowing arbitrary code injection into a `PHP eval()` call that can be exploited by unauthenticated attackers.
date: "2026-07-29T11:19:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - rce
  - web-exploitation
  - cve
products:
  - Cost Calculator Builder PRO plugin (<= 4.0.3)
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to execute code on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: which is injected verbatim into a calculator formula string passed to PHP eval() inside js_to_php()
    confidence_band: high
cves:
  - id: CVE-2026-14900
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14900
rules:
  - title: Detects CVE-2026-14900 Exploitation - Cost Calculator Builder PRO RCE Attempt
    description: Detects CVE-2026-14900 exploitation - Unauthenticated RCE in Cost Calculator Builder PRO WordPress plugin via `orderDetails[*].originalValue` leading to `PHP eval()`.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical remote code execution (RCE) vulnerability, tracked as CVE-2026-14900, affects all versions up to and including 4.0.3 of the Cost Calculator Builder PRO plugin for WordPress. This flaw stems from inadequate sanitization of the `orderDetails[*].originalValue` field, which is directly injected into a calculator formula string passed to `PHP eval()` within the plugin's `js_to_php` function. The plugin's `evaluateFormula()` function's regex allow-list only filters alphanumeric tokens, leaving non-word punctuation characters intact, thus enabling arbitrary code injection. While a nonce check is present, the required nonce is publicly exposed on every front-end page via the `wp_head` hook, making it easily obtainable by unauthenticated attackers. Successful exploitation allows an attacker to execute code on the server, potentially leading to full system compromise, data exfiltration, or website defacement. Organizations using this plugin are urged to patch immediately.

## Attack Chain

1. An unauthenticated attacker accesses any front-end page of a WordPress site running the vulnerable Cost Calculator Builder PRO plugin to retrieve the publicly emitted nonce.
2. The attacker crafts a malicious payload, embedding PHP code within the `orderDetails[*].originalValue` field, leveraging non-word punctuation characters or XOR gadgets to bypass existing sanitization mechanisms.
3. The attacker sends a specially crafted HTTP POST request to a vulnerable endpoint within the Cost Calculator Builder PRO plugin, including the stolen nonce and the malicious `orderDetails[*].originalValue` payload.
4. The `js_to_php` function within the plugin receives and processes the incoming request, including the unsanitized `orderDetails[*].originalValue`.
5. The malicious payload, now part of a formula string, is passed to the `PHP eval()` function for execution.
6. The `eval()` function executes the attacker's injected PHP code on the underlying web server.
7. The attacker achieves unauthenticated Remote Code Execution (RCE), gaining control over the compromised WordPress instance and potentially the server.

## Impact

Successful exploitation of CVE-2026-14900 grants unauthenticated attackers remote code execution capabilities on the affected WordPress server. This level of access can lead to a complete compromise of the website, including data theft, defacement, injection of malicious content, and establishing persistence for further attacks. Attackers can leverage the compromised server as a platform for lateral movement within the network or to launch attacks against other systems. Organizations using this plugin could face significant operational disruption, reputational damage, and regulatory penalties due to data breaches. The CVSS v3.1 base score of 9.8 indicates critical severity and ease of exploitation.

## Recommendation

* Immediately update the Cost Calculator Builder PRO plugin to a patched version beyond 4.0.3 to mitigate CVE-2026-14900.
* Deploy the Sigma rule "Detects CVE-2026-14900 Exploitation - Cost Calculator Builder PRO RCE Attempt" to your SIEM system to detect attempted exploitation of this vulnerability.
* Enable comprehensive `webserver` logging for all WordPress instances, focusing on HTTP POST requests, URI query parameters, and server response codes to aid in forensic analysis and detection.
* Monitor `process_creation` logs on web servers for unusual child processes spawned by the web server user (e.g., `php-fpm`, `apache`, `nginx`) that could indicate successful RCE.
