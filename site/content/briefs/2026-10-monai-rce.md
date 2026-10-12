---
title: Remote Code Execution in MONAI via Insecure Deserialization of Pretrained Weights
slug: 2026-10-monai-rce
description: MONAI versions prior to 1.6.1 are vulnerable to remote code execution due to insecure deserialization of pretrained weights fetched over plaintext HTTP.
date: "2026-10-12T18:38:09Z"
lastmod: "2026-10-12T18:38:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:monai:monai:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - deserialization
  - python
  - remote-code-execution
  - monai
vendors:
  - MONAI
products:
  - MONAI (0.4.0 - 1.6.0)
  - MONAI (< 1.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MONAI versions prior to 1.6.1 are vulnerable to remote code execution due to insecure deserialization.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The unpickling process executes arbitrary code during model construction.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The application unpickles a file path sourced from a user-modifiable JSON file without sufficient validation, allowing an attacker to trigger arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-109360
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109360
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109361
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade MONAI to version 1.6.1 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-109360 patch availability
  mitigation_plan:
    - priority: immediate
      action: Enforce HTTPS for all external model weight downloads
      owner: Network Security
      addresses: CVE-2026-109360
      evidence: Source states vulnerability relies on plaintext HTTP
updates:
  - at: "2026-10-12T18:38:16Z"
    level: L2
    summary: added coverage for MONAI (< 1.6.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109361
---

MONAI (Medical Open Network for Artificial Intelligence) versions 0.4.0 through 1.6.0 are vulnerable to remote code execution (CVE-2026-109360). The vulnerability stems from the use of plaintext HTTP to fetch pretrained model weights (specifically for SENet architectures) and the subsequent use of the PyTorch `load_state_dict_from_url` utility without the `weights_only=True` parameter. 

An on-path attacker capable of intercepting network traffic can replace the legitimate pretrained weight file with a crafted malicious .pth file. When the MONAI library attempts to construct a model using `pretrained=True`, it triggers the `pickle` module to deserialize the malicious object, leading to arbitrary code execution within the environment running the MONAI inference or training pipeline. This is particularly relevant for environments that automate model weight downloads from external repositories.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user or service account running the MONAI model pipeline. This could lead to full system compromise, data exfiltration from the research environment, or manipulation of diagnostic medical data. While the vulnerability requires an on-path position, it poses a significant risk to automated research workflows that trust remote weight sources.

## Recommendation

1. Upgrade MONAI to version 1.6.1 or later immediately to benefit from hardened weight-loading practices.
2. Implement strict network controls, such as enforcing HTTPS for all model weight downloads, to mitigate the ability of on-path attackers to perform file substitution.
3. Audit Python codebases for instances of `load_state_dict_from_url` and ensure the `weights_only=True` parameter is explicitly enabled to prevent the unpickling of arbitrary Python objects.
4. Implement integrity verification (such as SHA-256 hash checks) for all downloaded model weights prior to passing them to model construction utilities.
