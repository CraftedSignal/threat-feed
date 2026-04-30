---
title: Spring AI SimpleVectorStore SpEL Injection Vulnerability (CVE-2026-22738)
slug: 2026-03-spring-ai-spel-injection
description: A SpEL injection vulnerability exists in Spring AI's SimpleVectorStore when a user-supplied value is used as a filter expression key, potentially allowing malicious actors to execute arbitrary code in vulnerable applications.
date: "2026-03-27T06:16:37Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - spel-injection
  - spring-ai
  - cve-2026-22738
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22738
  - https://spring.io/security/cve-2026-22738
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious SpEL Expression in HTTP URI
    description: Detects suspicious SpEL expressions in HTTP URI, indicative of potential SpEL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious SpEL Expression in HTTP Body
    description: Detects suspicious SpEL expressions in HTTP Body, indicative of potential SpEL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SpEL (Spring Expression Language) injection vulnerability, identified as CVE-2026-22738, has been discovered in the SimpleVectorStore component of Spring AI. This flaw occurs when a user-supplied value is used as a filter expression key within SimpleVectorStore. Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code on the affected system. The vulnerability affects Spring AI versions 1.0.0 before 1.0.5 and 1.1.0 before 1.1.4. Only applications that…
