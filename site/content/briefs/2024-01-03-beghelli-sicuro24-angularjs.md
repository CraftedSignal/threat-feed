---
title: Beghelli Sicuro24 SicuroWeb AngularJS Sandbox Escape via Template Injection
slug: 2024-01-03-beghelli-sicuro24-angularjs
description: Beghelli Sicuro24 SicuroWeb is vulnerable to arbitrary JavaScript execution due to embedding an end-of-life AngularJS 1.5.2 component with known sandbox escape primitives combined with template injection, enabling attackers to compromise operator browser sessions via MITM attacks.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-41468
  - angularjs
  - template-injection
  - mitm
vendors:
  - Beghelli
products:
  - Sicuro24 SicuroWeb
  - AngularJS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-41468
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41468
rules:
  - title: Detect Suspicious AngularJS Template Injection
    description: Detects suspicious AngularJS template injection attempts in HTTP requests based on the presence of common template expressions.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Plaintext HTTP Traffic
    description: Detects unencrypted HTTP traffic on standard ports, which can enable MITM attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1588
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Beghelli Sicuro24 SicuroWeb is vulnerable due to its inclusion of AngularJS version 1.5.2, which is an end-of-life component with known sandbox escape primitives. This vulnerability, tracked as CVE-2026-41468, can be exploited via template injection present within the SicuroWeb application. When combined, these vulnerabilities allow a network-adjacent attacker to bypass the AngularJS sandbox and achieve arbitrary JavaScript execution within the browser sessions of SicuroWeb operators. The attack is facilitated by plaintext HTTP deployments, where a man-in-the-middle (MITM) attacker can inject the malicious payload without requiring active user interaction. This issue exposes operators to potential session hijacking, DOM manipulation, and persistent browser compromise.

## Attack Chain

1. Attacker positions themselves as a Man-in-the-Middle (MITM) on the network.
2. Operator initiates a session with the vulnerable Beghelli Sicuro24 SicuroWeb application over plaintext HTTP.
3. The MITM attacker intercepts the HTTP traffic between the operator and the SicuroWeb application.
4. The attacker injects a malicious AngularJS template injection payload into the HTTP response destined for the operator's browser.
5. The operator's browser processes the injected HTTP response, rendering the malicious AngularJS template.
6. The injected AngularJS template leverages known sandbox escape primitives present in AngularJS 1.5.2.
7. The sandbox escape allows the attacker to execute arbitrary JavaScript code within the operator's browser session.
8. The attacker uses the arbitrary JavaScript execution to perform actions such as session hijacking, DOM manipulation for credential harvesting, or establishing persistent browser compromise.

## Impact

Successful exploitation of CVE-2026-41468 can lead to significant compromise of Beghelli Sicuro24 SicuroWeb operator sessions. An attacker can hijack active sessions, steal credentials through DOM manipulation, or establish persistent control over the operator's browser. Due to the lack of specific victim numbers or sector targeting information, the potential scope of damage is difficult to quantify but highly dependent on the privileges associated with compromised operator accounts. A successful attack could enable unauthorized access to sensitive data, system configurations, or control functions managed by the SicuroWeb application.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious AngularJS Template Injection` to identify potential exploitation attempts against web applications leveraging AngularJS, focusing on HTTP requests containing suspicious template expressions.
*   Implement network monitoring for HTTP traffic to detect potential MITM attacks, focusing on connections to the SicuroWeb application, using the rule `Detect Plaintext HTTP Traffic`.
*   Upgrade Beghelli Sicuro24 SicuroWeb to a version that no longer utilizes AngularJS 1.5.2 or implement a robust Content Security Policy (CSP) to mitigate the impact of potential template injection attacks.
