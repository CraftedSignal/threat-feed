---
title: Fosowl agenticSeek 0.1.0 Code Injection Vulnerability (CVE-2026-5584)
slug: 2026-04-fosowl-code-injection
description: A code injection vulnerability (CVE-2026-5584) exists in Fosowl agenticSeek 0.1.0, allowing remote attackers to execute arbitrary code by manipulating the query endpoint through the PyInterpreter.execute function.
date: "2026-04-05T17:16:57Z"
severities:
  - critical
exploited: true
tags:
  - code-injection
  - vulnerability
  - fosowl
  - cve-2026-5584
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-5584
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5584
rules:
  - title: Detect Fosowl agenticSeek Code Injection Attempt
    description: Detects potential code injection attempts targeting the query endpoint in Fosowl agenticSeek 0.1.0
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Fosowl agenticSeek Code Injection Attempt - POST
    description: Detects potential code injection attempts targeting the query endpoint in Fosowl agenticSeek 0.1.0 (POST method)
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Fosowl agenticSeek version 0.1.0 is vulnerable to code injection (CVE-2026-5584). The vulnerability lies within the `PyInterpreter.execute` function in the `sources/tools/PyInterpreter.py` file, specifically related to the query endpoint. An unauthenticated attacker can exploit this flaw to inject and execute arbitrary code remotely. The vulnerability was reported to the vendor, but they did not respond, and a public exploit is available, increasing the risk of active exploitation. This poses a…
