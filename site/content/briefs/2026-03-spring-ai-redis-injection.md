---
title: Spring AI Redis Store TAG Injection Vulnerability (CVE-2026-22744)
slug: 2026-03-spring-ai-redis-injection
description: CVE-2026-22744 is a code injection vulnerability in Spring AI's RedisFilterExpressionConverter which allows an attacker to inject arbitrary commands into RediSearch TAG blocks via unescaped user-controlled strings, affecting versions 1.0.0 before 1.0.5 and 1.1.0 before 1.1.4.
date: "2026-03-27T06:16:38Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - injection
  - spring-ai
  - redis
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22744
  - https://spring.io/security/cve-2026-22744
rules:
  - title: Detect Potential Redis Injection Attempts via Web Request
    description: Detects suspicious web requests that may be attempting to inject Redis commands through filter parameters targeting Spring AI applications.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect RediSearch TAG Injection in Web Logs
    description: This rule detects potential RediSearch TAG injection attempts by monitoring web server logs for specific patterns indicative of command injection.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-22744 is a critical vulnerability found within the `RedisFilterExpressionConverter` of the Spring AI Redis Store. The vulnerability arises because the `stringValue()` function directly inserts user-supplied strings into the `@field:{VALUE}` RediSearch TAG block without proper sanitization or escaping. This allows an attacker to inject arbitrary commands or data into the Redis database if they can control the input used as a filter value for a TAG field. This vulnerability affects…
