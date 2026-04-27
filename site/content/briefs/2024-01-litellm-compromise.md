---
title: Compromised Litellm PyPI Package Versions
slug: 2024-01-litellm-compromise
description: Versions 1.82.7 and 1.82.8 of the Litellm package on PyPI were compromised in a supply chain attack, potentially impacting numerous users, with recommendations to avoid updating to these versions.
date: "2026-03-24T12:12:58Z"
severities:
  - high
tags:
  - supply-chain
  - pypi
  - litellm
  - compromise
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.reddit.com/r/cybersecurity/comments/1s2c0sj/litellm_1827_and_1828_on_pypi_are_compromised_do/
  - https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
ioc_counts:
  url: 1
rules:
  - title: Suspicious Process Spawned by Python
    description: Detects suspicious processes spawned by python executables, which may indicate malicious code execution within a compromised Python package.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Connection from Python
    description: Detects suspicious outbound network connections initiated from Python processes, potentially indicating C2 activity from a compromised Python package.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 24, 2026, versions 1.82.7 and 1.82.8 of the Litellm package, available on the Python Package Index (PyPI), were reported as compromised. This supply chain attack potentially affects thousands of users who may have updated to the malicious versions. The compromised packages could contain malicious code injected by an unknown threat actor. Users are advised to avoid updating to these versions and investigate their systems for potential compromise. The initial report came from a Reddit…
