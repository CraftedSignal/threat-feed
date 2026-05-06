---
title: Valtimo SpEL Injection Vulnerability Allows Remote Code Execution
slug: 2026-05-valtimo-spel
description: Valtimo is vulnerable to SpEL injection via StandardEvaluationContext, which allows Remote Code Execution by admin users who can execute arbitrary OS commands and exfiltrate sensitive information.
date: "2026-05-07T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - spel-injection
  - rce
  - valtimo
vendors:
  - Ritense
products:
  - Valtimo document module
  - Valtimo case module
  - Valtimo contract module
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
references:
  - https://github.com/advisories/GHSA-j7j9-5253-f7vh
rules:
  - title: Detect Valtimo SpEL Injection via Document Migration
    description: Detects attempts to exploit the SpEL injection vulnerability in Valtimo's DocumentMigrationService via suspicious POST requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Valtimo SpEL Injection via Condition Framework
    description: Detects attempts to exploit the SpEL injection vulnerability in Valtimo's Condition framework by looking for suspicious patterns in HTTP POST requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Valtimo, a low-code application development platform, is susceptible to Spring Expression Language (SpEL) injection due to the usage of `StandardEvaluationContext` in multiple classes. This vulnerability, affecting versions 12.0.0 through 13.22.0, allows authenticated users with administrative privileges to inject arbitrary SpEL expressions, leading to remote code execution (RCE). The vulnerability is present in the document migration service (versions 12.0.0-12.31.0) and within the condition framework (versions 13.4.0-13.22.0), which is used across multiple modules in later versions. An attacker leveraging this vulnerability can execute arbitrary OS commands, exfiltrate environment variables containing sensitive information, read JVM system properties, and load arbitrary classes, impacting the confidentiality, integrity, and availability of the Valtimo platform.

## Attack Chain

1. An attacker authenticates to the Valtimo platform with administrative credentials.
2. The attacker crafts a malicious SpEL expression, embedding OS commands within the expression (e.g., `T(java.lang.Runtime).getRuntime().exec('...')`).
3. For DocumentMigrationService (versions 12.0.0-12.31.0), the attacker sends a `POST` request to `/api/management/v1/document-definition/migrate` or `/api/management/v1/document-definition/migration/conflicts`.
4. The malicious SpEL expression is injected via the `source` or `target` field of a `DocumentMigrationPatch` object in the request body, using the `${...}` template syntax.
5. For Condition framework (versions 13.4.0-13.22.0), the attacker configures a widget, dashboard, or feature that uses the `Condition` framework, injecting the SpEL expression in the `value` field of a condition's JSON configuration.
6. The application processes the request containing the malicious SpEL expression using the vulnerable `StandardEvaluationContext`.
7. The injected SpEL expression is evaluated, leading to the execution of arbitrary OS commands on the server.
8. The attacker achieves remote code execution, potentially gaining complete control over the Valtimo platform.

## Impact

Successful exploitation of this vulnerability allows an attacker with administrative privileges to execute arbitrary OS commands on the Valtimo server. This can lead to complete system compromise, including the exfiltration of sensitive data like database passwords, API keys, and Keycloak secrets stored as environment variables. The vulnerability affects Valtimo instances running versions 12.0.0-12.31.0 (document module) and 13.4.0-13.22.0 (condition framework). A successful attack can result in significant data breaches, service disruption, and reputational damage.

## Recommendation

*   Upgrade Valtimo document module to version 12.32.0 or later to remediate the vulnerability in DocumentMigrationService.
*   Upgrade Valtimo case and contract modules to version 13.23.0 or later to remediate the vulnerability in the Condition framework.
*   Deploy the Sigma rule "Detect Valtimo SpEL Injection via Document Migration" to detect attempts to exploit the DocumentMigrationService vulnerability via suspicious POST requests to the API endpoints.
*   Enable webserver logging to capture POST request data, which is necessary to identify potentially malicious SpEL expressions being sent to the affected endpoints.
