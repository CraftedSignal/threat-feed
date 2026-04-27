---
title: Spinnaker Echo Service Vulnerable to Spring Expression Language Injection
slug: 2026-04-spinnaker-spel
description: Unrestricted access to the JVM via Spring Expression Language (SPeL) in Spinnaker's Echo service allows for arbitrary code execution, enabling attackers to invoke commands and access files.
date: "2026-04-20T21:19:10Z"
severities:
  - critical
tags:
  - spel
  - code-execution
  - cloud
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-32613
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32613
rules:
  - title: Detect Spinnaker Echo SpEL Injection Attempts via Web Logs
    description: Detects potential SpEL injection attempts in Spinnaker Echo service by monitoring web server logs for suspicious patterns in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Spinnaker Echo SpEL Injection via POST Request
    description: Detects potential SpEL injection attempts in Spinnaker Echo service POST requests by monitoring web server logs for suspicious patterns in HTTP request bodies.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Spinnaker is an open-source, multi-cloud continuous delivery platform. The Echo service, like other services within Spinnaker, utilizes Spring Expression Language (SPeL) for processing information, specifically concerning expected artifacts. However, versions prior to 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2 did not restrict the context of SPeL to a set of trusted classes, granting full JVM access, unlike Orca. This unrestricted access enables a user to leverage arbitrary Java classes…
