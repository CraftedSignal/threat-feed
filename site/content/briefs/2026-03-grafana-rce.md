---
title: Grafana Remote Code Execution and Denial-of-Service Vulnerabilities
slug: 2026-03-grafana-rce
description: Critical CVE-2026-27876 allows remote code execution in Grafana instances with the sqlExpressions feature enabled, while high severity CVE-2026-27880 can trigger out-of-memory crashes via the OpenFeature endpoint, requiring immediate patching to prevent compromise and service disruption.
date: "2026-03-30T19:10:23Z"
severities:
  - critical
tags:
  - grafana
  - rce
  - dos
  - vulnerability
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: Endpoint Denial of Service
references:
  - https://ccb.belgium.be/advisories/warning-remote-code-execution-injection-vulnerabilities-grafana-patch-immediately
  - https://grafana.com/blog/grafana-security-release-critical-and-high-severity-security-fixes-for-cve-2026-27876-and-cve-2026-27880/
  - https://grafana.com/security/security-advisories/cve-2026-27876/
  - https://grafana.com/security/security-advisories/cve-2026-27880/
rules:
  - title: Detect Grafana OpenFeature Endpoint DoS Attempt
    description: Detects potential attempts to exploit CVE-2026-27880 by monitoring requests to the OpenFeature feature-toggle evaluation endpoint with unusually large request bodies.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Grafana SQL Expression Injection Attempt
    description: Detects suspicious POST requests indicative of SQL injection attempts in Grafana by monitoring for SQL keywords in the query parameters of API endpoints related to SQL Expressions.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-27876, has been identified in Grafana, a widely-used monitoring and observability platform. This vulnerability allows for remote arbitrary code execution when chained with SQL Expressions and a Grafana Enterprise plugin. The vulnerability affects instances where the sqlExpressions feature toggle is enabled, and has a CVSS score of 9.1. A separate, high severity vulnerability, CVE-2026-27880, exists in Grafana's OpenFeature feature-toggle evaluation…
