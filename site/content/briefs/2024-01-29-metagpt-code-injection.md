---
title: FoundationAgents MetaGPT Code Injection Vulnerability (CVE-2026-5971)
slug: 2024-01-29-metagpt-code-injection
description: A code injection vulnerability exists in FoundationAgents MetaGPT <= 0.8.1 within the ActionNode.xml_fill function, allowing remote attackers to inject code due to improper neutralization of directives in dynamically evaluated code.
date: "2026-04-09T18:17:04Z"
severities:
  - high
tags:
  - code-injection
  - vulnerability
  - metagpt
  - CVE-2026-5971
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5971
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5971
rules:
  - title: Detect MetaGPT XML Injection Attempt
    description: Detects potential XML injection attempts against MetaGPT by monitoring for suspicious patterns in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect MetaGPT Suspicious Child Processes
    description: Detects suspicious child processes spawned by MetaGPT, indicating potential post-exploitation activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A code injection vulnerability, identified as CVE-2026-5971, has been discovered in FoundationAgents MetaGPT versions up to 0.8.1. The vulnerability resides in the `ActionNode.xml_fill` function within the `metagpt/actions/action_node.py` file, specifically related to the XML Handler component. This flaw allows a remote attacker to inject malicious code by exploiting improper neutralization of directives in dynamically evaluated code. A proof-of-concept exploit is publicly available, increasing…
