---
title: Beghelli Sicuro24 SicuroWeb AngularJS Sandbox Escape via Template Injection
slug: 2024-01-03-beghelli-sicuro24-angularjs
description: Beghelli Sicuro24 SicuroWeb is vulnerable to arbitrary JavaScript execution due to embedding an end-of-life AngularJS 1.5.2 component with known sandbox escape primitives combined with template injection, enabling attackers to compromise operator browser sessions via MITM attacks.
date: "2024-01-03T12:00:00Z"
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

Beghelli Sicuro24 SicuroWeb is vulnerable due to its inclusion of AngularJS version 1.5.2, which is an end-of-life component with known sandbox escape primitives. This vulnerability, tracked as CVE-2026-41468, can be exploited via template injection present within the SicuroWeb application. When combined, these vulnerabilities allow a network-adjacent attacker to bypass the AngularJS sandbox and achieve arbitrary JavaScript execution within the browser sessions of SicuroWeb operators. The…
