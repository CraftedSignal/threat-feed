---
title: 'CVE-2026-8759: xiandafu beetl SpEL Injection Vulnerability'
slug: 2026-05-beetl-spel-injection
description: CVE-2026-8759 is a remote code execution vulnerability in xiandafu beetl up to 3.20.2, stemming from improper neutralization of special elements within the SpELFunction component, enabling remote exploitation.
date: "2026-05-17T15:18:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - spel-injection
  - rce
  - java
  - cve
vendors:
  - xiandafu
products:
  - beetl
  - beetl-spring-classic
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Services
cves:
  - id: CVE-2026-8759
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8759
  - CVE-2026-8759
rules:
  - title: Detects CVE-2026-8759 Exploitation - Beetl SpEL Injection Attempt
    description: Detects CVE-2026-8759 exploitation - Attempts to exploit the Beetl SpEL injection vulnerability by identifying suspicious request parameters
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
  - title: Detects CVE-2026-8759 Exploitation - Beetl SpEL Injection Attempt (URI)
    description: Detects CVE-2026-8759 exploitation - Attempts to exploit the Beetl SpEL injection vulnerability by identifying suspicious URI stems and query parameters
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, CVE-2026-8759, has been identified in xiandafu beetl version 3.20.2 and earlier. The vulnerability resides in the `SpELFunction.java` file of the `beetl-classic-integration/beetl-spring-classic/src/main/java/org/beetl/ext/spring/` component, specifically within the `SpELFunction` class. Successful exploitation enables remote attackers to inject and execute arbitrary code by manipulating special elements in an expression language statement. The existence of a publicly available exploit increases the risk of widespread exploitation. The vendor has been notified about the vulnerability, but there has been no response as of the time of this writing.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of xiandafu beetl (<= 3.20.2) with the SpELFunction component enabled.
2. The attacker crafts a malicious HTTP request targeting an endpoint that utilizes the vulnerable SpELFunction.
3. Within the request, the attacker injects a specially crafted expression language statement containing malicious code. This injection targets the component that handles the SpELFunction, specifically the `SpELFunction.java` file.
4. The application processes the request, passing the attacker-controlled expression language statement to the SpELFunction for evaluation.
5. Due to the improper neutralization of special elements, the injected malicious code is executed by the application server.
6. The attacker gains arbitrary code execution within the context of the application, allowing them to perform actions such as installing malware, reading sensitive data, or modifying system configurations.
7. The attacker establishes a persistent connection to the compromised system for further exploitation.
8. The attacker pivots to other internal systems, escalating their access and control within the network.

## Impact

Successful exploitation of CVE-2026-8759 allows an attacker to achieve remote code execution on systems running vulnerable versions of xiandafu beetl. This can lead to complete system compromise, data breaches, and potential disruption of services. Due to the ease of exploitation (publicly available exploit) and the lack of vendor response, this vulnerability poses a significant risk to organizations using the affected software.

## Recommendation

*   Upgrade to a patched version of xiandafu beetl that addresses CVE-2026-8759, if one becomes available.
*   Apply input validation and sanitization to all user-supplied input to prevent expression language injection.
*   Deploy the Sigma rule "Detects CVE-2026-8759 Exploitation - Beetl SpEL Injection Attempt" to your SIEM to detect potential exploitation attempts.
*   Monitor web server logs for suspicious activity, such as requests containing expression language syntax, as detected by the Sigma rule "Detects CVE-2026-8759 Exploitation - Beetl SpEL Injection Attempt (URI)".
*   Implement network segmentation to limit the potential impact of a successful exploit.
