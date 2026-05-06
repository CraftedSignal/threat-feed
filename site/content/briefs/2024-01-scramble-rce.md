---
title: Scramble Remote Code Execution via User-Controlled Input
slug: 2024-01-scramble-rce
description: Scramble versions 0.13.2 through 0.13.21 are vulnerable to remote code execution due to the evaluation of user-controlled input in validation rules during documentation generation, potentially allowing attackers to execute arbitrary PHP code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - php
vendors:
  - composer
products:
  - scramble (0.13.2 - 0.13.21)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
references:
  - https://github.com/advisories/GHSA-4rm2-28vj-fj39
rules:
  - title: Detect Access to Scramble Documentation Endpoints
    description: Detects access to the Scramble documentation endpoints, which may indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Code Injection Attempts in URI Query
    description: Detects attempts to inject PHP code in the URI query string, potentially targeting the Scramble vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Code Injection Attempts in URI Stem
    description: Detects attempts to inject PHP code in the URI stem, potentially targeting the Scramble vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 3
---

A remote code execution vulnerability, identified as CVE-2026-44262, affects Scramble versions 0.13.2 up to 0.13.21. This flaw stems from the evaluation of user-controlled input within validation rules when documentation endpoints are publicly accessible. Specifically, during the generation of API documentation, request supplied data that is referenced in the validation rules can be evaluated, resulting in the execution of arbitrary PHP code within the application's context. This vulnerability allows unauthenticated attackers to potentially gain full control of the affected system. The issue has been addressed in Scramble version 0.13.22. Defenders should prioritize patching to mitigate the risk of exploitation.

## Attack Chain

1.  An attacker identifies a Scramble application running a vulnerable version (0.13.2 - 0.13.21) with publicly accessible documentation endpoints, such as `/docs/api` or `/docs/api.json`.
2.  The attacker analyzes the application's validation rules to identify endpoints that utilize user-controlled input (e.g., request parameters) within validation expressions.
3.  The attacker crafts a malicious HTTP request containing a payload designed to inject PHP code into the validation rule's expression.
4.  The crafted request is sent to an endpoint that triggers the vulnerable validation rule.
5.  During the documentation generation process, Scramble evaluates the malicious input, leading to the execution of the injected PHP code.
6.  The attacker's PHP code executes within the application's context, potentially allowing them to read sensitive files, execute system commands, or establish a reverse shell.
7.  The attacker leverages the gained access to move laterally within the network, escalate privileges, or exfiltrate sensitive data.
8.  The attacker achieves their final objective, such as data theft, system compromise, or denial of service.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary PHP code on the affected server. This can lead to complete system compromise, including data theft, modification, or destruction. Given the nature of RCE vulnerabilities, the impact is considered critical. The number of affected systems depends on the prevalence of Scramble within publicly accessible environments, but any unpatched instance is at risk.

## Recommendation

*   Upgrade Scramble to version 0.13.22 or later to patch CVE-2026-44262.
*   Restrict access to documentation endpoints (`/docs/api`, `/docs/api.json`) to trusted networks or users as a workaround if patching is not immediately feasible.
*   Review and eliminate the use of user-controlled variables inside validation rule expressions, as suggested in the advisory.
*   Implement a web application firewall (WAF) rule to detect and block requests containing potentially malicious PHP code in request parameters.
