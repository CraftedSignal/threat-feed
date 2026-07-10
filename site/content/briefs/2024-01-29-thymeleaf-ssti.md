---
title: Thymeleaf Server-Side Template Injection Vulnerability
slug: 2024-01-29-thymeleaf-ssti
description: Thymeleaf versions up to 3.1.3.RELEASE are vulnerable to server-side template injection (SSTI) due to improper neutralization of specific syntax patterns, allowing attackers to execute unauthorized expressions when unvalidated user input is passed directly to the template engine.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - thymeleaf
  - ssti
  - cve-2026-40478
  - server-side template injection
  - expression injection
vendors:
  - Thymeleaf
products:
  - Thymeleaf
  - Thymeleaf Spring 5
  - Thymeleaf Spring 6
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-xjw8-8c5c-9r79
rules:
  - title: Detect Suspicious Thymeleaf Expression Injection
    description: Detects potential Server-Side Template Injection (SSTI) attempts in Thymeleaf applications by identifying suspicious expression patterns in web server logs.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Thymeleaf Expression Injection (POST)
    description: Detects potential Server-Side Template Injection (SSTI) attempts in Thymeleaf applications by identifying suspicious expression patterns in web server logs using POST requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Thymeleaf, a widely used Java template engine, contains a critical security vulnerability (CVE-2026-40478) affecting versions up to 3.1.3.RELEASE. This vulnerability stems from the improper neutralization of specific syntax patterns within the expression execution mechanisms.  An attacker can exploit this flaw by injecting malicious expressions into Thymeleaf templates if the application passes unvalidated user-supplied input directly to the template engine. Successful exploitation allows an unauthenticated remote attacker to bypass the library's protections and achieve Server-Side Template Injection (SSTI), potentially leading to remote code execution.  The vulnerability affects multiple Thymeleaf packages including `org.thymeleaf:thymeleaf`, `org.thymeleaf:thymeleaf-spring5`, and `org.thymeleaf:thymeleaf-spring6`. It is strongly recommended to upgrade to version 3.1.4.RELEASE to mitigate this risk.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of Thymeleaf (<= 3.1.3.RELEASE) that processes user-supplied input within a Thymeleaf template.
2. The attacker crafts a malicious payload containing Thymeleaf expression language syntax, specifically targeting the bypassable syntax patterns.
3. The attacker injects the crafted payload into a user-input field, such as a form parameter, URL parameter, or HTTP header, that is directly processed by the Thymeleaf template engine without proper validation or sanitization.
4. The vulnerable Thymeleaf engine processes the malicious payload, failing to properly neutralize the dangerous syntax patterns.
5. The injected expression is evaluated by the server, granting the attacker the ability to execute arbitrary code within the context of the application.
6. The attacker leverages the remote code execution capability to gain control of the server, potentially installing malware, accessing sensitive data, or pivoting to other systems within the network.
7. The attacker may establish persistent access by creating new user accounts, modifying system configurations, or deploying backdoors.

## Impact

Successful exploitation of this SSTI vulnerability allows an unauthenticated remote attacker to execute arbitrary code on the server hosting the vulnerable application.  This can lead to complete system compromise, including data theft, malware deployment, and denial of service. The severity is considered critical because it allows for remote code execution without authentication. Applications in any sector are vulnerable if they use Thymeleaf and pass user-provided input unsanitized to the template engine.

## Recommendation

*   Upgrade Thymeleaf to version 3.1.4.RELEASE or later to patch the vulnerability (CVE-2026-40478).
*   Implement robust input validation and sanitization on all user-supplied data before passing it to the Thymeleaf template engine to prevent expression injection.
*   Deploy the Sigma rule `Detect Suspicious Thymeleaf Expression Injection` to identify attempts to exploit this vulnerability in web server logs.
*   Continuously monitor web application logs for unusual patterns and potential exploitation attempts related to Thymeleaf expressions.
