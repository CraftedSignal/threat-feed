---
title: PraisonAI Arbitrary Code Execution Vulnerability
slug: 2026-04-praisonai-code-exec
description: PraisonAI versions 4.5.138 and below are vulnerable to arbitrary code execution due to the unsanitized import of a malicious tools.py file, leading to potential system compromise.
date: "2026-04-14T04:18:15Z"
severities:
  - critical
tags:
  - praisonai
  - code-execution
  - cve-2026-40287
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40287
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40287
rules:
  - title: Detect tools.py Creation in PraisonAI Directory
    description: Detects the creation of a tools.py file in directories commonly used by PraisonAI, indicating potential exploitation of CVE-2026-40287.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect PraisonAI Importing tools.py
    description: Detects the PraisonAI process importing the 'tools.py' file, which is abnormal behavior that could be related to CVE-2026-40287
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - image_load
      - windows
rules_count: 2
---

PraisonAI, a multi-agent teams system, is vulnerable to arbitrary code execution in versions 4.5.138 and below. The vulnerability stems from the automatic and unsanitized import of a `tools.py` file from the current working directory during application startup. Specifically, components like `call.py` (via `import_tools_from_file()`), `tool_resolver.py` (via `_load_local_tools()`), and command-line tool loading paths directly import `./tools.py` without validation, sandboxing, or user…
