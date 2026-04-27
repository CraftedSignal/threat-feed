---
title: PowerJob OpenAPI Endpoint Code Injection Vulnerability (CVE-2026-5739)
slug: 2026-04-powerjob-code-injection
description: A code injection vulnerability exists in PowerJob versions 5.1.0, 5.1.1, and 5.1.2, allowing remote attackers to execute arbitrary code via the GroovyEvaluator.evaluate function in the OpenAPI Endpoint component by manipulating the nodeParams argument.
date: "2026-04-07T20:16:34Z"
severities:
  - high
tags:
  - code-injection
  - powerjob
  - cve-2026-5739
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-5739
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5739
  - https://github.com/PowerJob/PowerJob/
  - https://github.com/PowerJob/PowerJob/issues/1168
  - https://vuldb.com/vuln/355747
rules:
  - title: Detect PowerJob Groovy Code Injection Attempt
    description: Detects potential attempts to exploit CVE-2026-5739 by identifying suspicious requests to the /openApi/addWorkflowNode endpoint with potentially malicious code in the nodeParams argument.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
      - T1505.001
    data_sources:
      - webserver
      - linux
  - title: PowerJob Suspicious Process Execution via Web Server
    description: Detects suspicious process execution originating from the web server, potentially indicating code injection exploitation in PowerJob.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical code injection vulnerability, identified as CVE-2026-5739, has been discovered in PowerJob, an open-source distributed job scheduling and management platform. This vulnerability affects versions 5.1.0, 5.1.1, and 5.1.2. The vulnerability resides in the `GroovyEvaluator.evaluate` function of the `/openApi/addWorkflowNode` endpoint within the OpenAPI component. By manipulating the `nodeParams` argument, a remote attacker can inject and execute arbitrary code on the server. This…
