---
title: MetaGPT Code Injection Vulnerability (CVE-2026-5970)
slug: 2026-04-metagpt-code-injection
description: A code injection vulnerability, CVE-2026-5970, exists in FoundationAgents MetaGPT up to version 0.8.1, allowing remote attackers to execute arbitrary code via manipulation of the `check_solution` function in the HumanEvalBenchmark/MBPPBenchmark component.
date: "2026-04-09T18:17:04Z"
severities:
  - high
tags:
  - code-injection
  - metagpt
  - cve-2026-5970
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-5970
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5970
  - https://github.com/FoundationAgents/MetaGPT/
  - https://github.com/FoundationAgents/MetaGPT/issues/1942
  - https://github.com/FoundationAgents/MetaGPT/pull/1988
  - https://vuldb.com/vuln/356524
rules:
  - title: Detect MetaGPT Suspicious Process Creation
    description: Detects suspicious process creation potentially related to MetaGPT exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - process_creation
      - windows
  - title: Detect MetaGPT Code Injection Attempt via Network
    description: Detects possible MetaGPT code injection attempts via network communication by looking for suspicious patterns in network data.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-5970 is a critical vulnerability affecting FoundationAgents MetaGPT, a framework for multi-agent systems, up to version 0.8.1. The vulnerability resides within the `check_solution` function of the `HumanEvalBenchmark/MBPPBenchmark` component. This flaw enables a remote attacker to inject and execute arbitrary code by manipulating input parameters. The vulnerability has been publicly disclosed and exploits are readily available. The maintainers of the MetaGPT project were notified via…
