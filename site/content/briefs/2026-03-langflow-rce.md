---
title: Critical RCE Vulnerability in Langflow AI Pipelines (CVE-2026-33017)
slug: 2026-03-langflow-rce
description: A critical remote code execution vulnerability, CVE-2026-33017, exists in Langflow AI pipelines prior to version 1.9.0 that allows an unauthenticated remote attacker to execute code with full server process privileges, impacting availability, integrity, and confidentiality.
date: "2026-03-24T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - langflow
  - rce
  - cve-2026-33017
  - ai-pipeline
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Scanning
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerability-langflow-ai-pipelines-patch-immediately
  - https://github.com/langflow-ai/langflow/security/advisories/GHSA-vwmf-pq79-vjvx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33017
  - https://www.sysdig.com/blog/cve-2026-33017-how-attackers-compromised-langflow-ai-pipelines-in-20-hours
rules:
  - title: Langflow Suspicious Process Execution
    description: Detects suspicious processes spawned by the Langflow process, indicative of potential RCE exploitation
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Langflow Reconnaissance Activity
    description: Detects potential scanning or reconnaissance attempts against Langflow instances.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1046
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A critical remote code execution vulnerability, CVE-2026-33017, affects Langflow AI pipelines prior to version 1.9.0. Langflow is a tool used for building and deploying AI-powered agents and workflows. The vulnerability resides in the `build_public_tmp` endpoint, which is intended to be unauthenticated for public flows. However, it incorrectly accepts attacker-supplied flow data, leading to remote code execution with full server process privileges. The vulnerability can be exploited by an…
