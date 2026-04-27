---
title: Critical Vulnerability in FastGPT Allows API Key Exfiltration and Internal Network Access
slug: 2026-04-fastgpt-vuln
description: CVE-2026-34162 in FastGPT allows unauthenticated attackers to exfiltrate API keys and gain complete access to internal services managed by Docker Compose by sending arbitrary HTTP requests, leading to potential compromise of the internal network.
date: "2026-04-01T16:12:02Z"
severities:
  - critical
tags:
  - fastgpt
  - vulnerability
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34162
    cvss: 10
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerability-fastgpt-patch-immediately
  - https://github.com/labring/FastGPT/security/advisories/GHSA-w36r-f268-pwrj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34162
ioc_counts:
  url: 1
rules:
  - title: Detect Access to FastGPT HTTP Testing Endpoint
    description: Detects unauthorized access to the FastGPT HTTP tools testing endpoint, which is vulnerable to CVE-2026-34162.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Requests via FastGPT Testing Endpoint
    description: Detects HTTP requests being made through the FastGPT testing endpoint, potentially indicating exploitation of CVE-2026-34162.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-34162, has been identified in FastGPT, a framework for building AI-powered applications. The vulnerability resides in the HTTP tools testing endpoint, which is accessible without authentication. This allows an unauthenticated attacker to send arbitrary server-side HTTP requests and receive the responses. If the default admin token is not changed, an attacker can access the proxy management API to exfiltrate third-party API keys. Furthermore, the attacker can…
