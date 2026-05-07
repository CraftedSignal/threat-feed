---
title: Spring AI Vulnerabilities CVE-2026-40967 and CVE-2026-40978
slug: 2026-04-spring-ai-vulns
description: Spring released security advisories on April 27, 2026, to address a VectorStore FilterExpression Converter injection vulnerability (CVE-2026-40967) and a SQL Injection vulnerability (CVE-2026-40978) in Spring AI versions prior to 1.0.6 and 1.1.5.
date: "2026-04-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - sql-injection
  - code-injection
  - spring-ai
vendors:
  - Spring
products:
  - Spring AI (1.0.x < 1.0.6)
  - Spring AI (1.1.x < 1.1.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40967
    cvss: 8.6
    epss: 0.00074
  - id: CVE-2026-40978
    cvss: 8.8
    epss: 0.00053
references:
  - https://cyber.gc.ca/en/alerts-advisories/spring-security-advisory-av26-397
  - https://spring.io/security/cve-2026-40967
  - https://spring.io/security/cve-2026-40978
  - https://spring.io/security
rules:
  - title: Detect Potential FilterExpression Injection Attempts in Spring AI (CVE-2026-40967)
    description: Detects suspicious FilterExpression patterns indicative of potential injection attacks targeting CVE-2026-40967 in Spring AI applications.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempts in CosmosDBVectorStore.doDelete() via Web Logs (CVE-2026-40978)
    description: This rule detects potential SQL injection attempts targeting the CosmosDBVectorStore.doDelete() function in Spring AI applications by analyzing web server logs for suspicious SQL syntax.
    platform: sigma
    severity: critical
    tactics:
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On April 27, 2026, Spring published security advisories addressing critical vulnerabilities within the Spring AI framework. Specifically, CVE-2026-40967 details a VectorStore FilterExpression Converter injection vulnerability, while CVE-2026-40978 outlines a SQL Injection flaw within the CosmosDBVectorStore.doDelete() function. These vulnerabilities affect Spring AI versions 1.0.x prior to 1.0.6 and 1.1.x prior to 1.1.5. Exploitation of these vulnerabilities could allow for unauthorized data access or modification, potentially leading to significant data breaches and system compromise. It is crucial for organizations utilizing Spring AI to apply the necessary updates promptly to mitigate these risks.

## Attack Chain

1.  Attacker identifies a vulnerable Spring AI instance running a version prior to 1.0.6 or 1.1.5.
2.  For CVE-2026-40967 (VectorStore FilterExpression Converter injection): the attacker crafts a malicious FilterExpression designed to inject arbitrary code during the conversion process.
3.  The malicious FilterExpression is submitted to the vulnerable VectorStore component via a user-controlled input or API endpoint.
4.  The VectorStore attempts to convert the FilterExpression, triggering the injection vulnerability.
5.  Arbitrary code is executed within the context of the Spring AI application, potentially granting the attacker control over the system.
6.  For CVE-2026-40978 (SQL Injection in CosmosDBVectorStore.doDelete()): The attacker crafts a SQL injection payload.
7.  The malicious SQL payload is inserted into the `doDelete()` function via a user-controlled input or API endpoint.
8.  The injected SQL code is executed against the CosmosDB database, enabling data exfiltration, modification, or deletion.

## Impact

Successful exploitation of CVE-2026-40967 and CVE-2026-40978 can lead to significant data breaches, unauthorized access to sensitive information, and complete compromise of the Spring AI application. This can impact any sector utilizing Spring AI for AI-powered applications, including finance, healthcare, and government. The impact could range from data theft and ransomware deployment to denial of service and reputational damage.

## Recommendation

*   Immediately upgrade Spring AI to version 1.0.6 or 1.1.5 or later to address CVE-2026-40967 and CVE-2026-40978.
*   Monitor web server logs (category `webserver`, product `linux`) for suspicious requests targeting Spring AI endpoints, looking for unusual FilterExpression patterns or SQL syntax, to identify potential exploitation attempts.
*   Implement input validation and sanitization measures within Spring AI applications to prevent FilterExpression injection and SQL injection attacks.
