---
title: vLLM Remote Code Execution Vulnerability (CVE-2026-27893)
slug: 2026-03-vllm-rce
description: vLLM versions before 0.18.0 are vulnerable to remote code execution due to hardcoded trust of remote code, even when explicitly disabled by the user, allowing attackers to execute arbitrary code via malicious model repositories.
date: "2026-03-27T00:16:22Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - vLLM
  - RCE
  - CVE-2026-27893
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27893
  - https://github.com/vllm-project/vllm/commit/00bd08edeee5dd4d4c13277c0114a464011acf72
  - https://github.com/vllm-project/vllm/pull/36192
  - https://github.com/vllm-project/vllm/security/advisories/GHSA-7972-pg2x-xr59
rules:
  - title: Detect Outbound Network Connection from vLLM to Uncommon Destinations
    description: Detects suspicious outbound network connections initiated from vLLM processes, potentially indicating a compromised instance attempting to download malicious model components or exfiltrate data.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Detect vLLM Process Creation
    description: Detects process creation events related to vLLM, useful for baseline monitoring and identifying anomalous executions.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

vLLM is an inference and serving engine for large language models (LLMs). Prior to version 0.18.0, specifically from version 0.10.1, a critical vulnerability exists. Two model implementation files within vLLM hardcode the setting `trust_remote_code=True` when loading sub-components of models. This design flaw bypasses the user's explicit security intention to disable remote code execution using the `--trust-remote-code=False` option. An attacker could craft a malicious model repository that…
