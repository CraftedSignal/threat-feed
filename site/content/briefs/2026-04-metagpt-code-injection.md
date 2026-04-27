---
title: MetaGPT Code Injection Vulnerability (CVE-2026-6110)
slug: 2026-04-metagpt-code-injection
description: A code injection vulnerability exists in FoundationAgents MetaGPT up to version 0.8.1, specifically affecting the generate_thoughts function in the metagpt/strategy/tot.py file of the Tree-of-Thought Solver component, allowing for remote exploitation with a publicly available exploit.
date: "2026-04-12T03:16:08Z"
severities:
  - high
tags:
  - code-injection
  - metagpt
  - cve-2026-6110
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-6110
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6110
  - https://github.com/FoundationAgents/MetaGPT/
  - https://github.com/FoundationAgents/MetaGPT/issues/1933
  - https://github.com/FoundationAgents/MetaGPT/pull/1946
  - https://vuldb.com/submit/791761
  - https://vuldb.com/vuln/356970
  - https://vuldb.com/vuln/356970/cti
rules:
  - title: Detect MetaGPT Code Injection Attempt
    description: Detects potential code injection attempts targeting the MetaGPT application through suspicious HTTP requests to the generate_thoughts function.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect MetaGPT Code Injection - Metagpt directory
    description: Detects potential code injection attempts by looking at the file path
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A code injection vulnerability, identified as CVE-2026-6110, affects FoundationAgents MetaGPT versions up to 0.8.1. The vulnerability resides in the `generate_thoughts` function within the `metagpt/strategy/tot.py` file, a part of the Tree-of-Thought Solver. This flaw enables attackers to inject arbitrary code and execute it within the context of the MetaGPT application. The vulnerability is remotely exploitable and a proof-of-concept exploit is publicly available, increasing the risk of…
