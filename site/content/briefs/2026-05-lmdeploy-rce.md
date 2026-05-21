---
title: LMDeploy Arbitrary Code Execution via Hardcoded trust_remote_code=True
slug: 2026-05-lmdeploy-rce
description: LMDeploy versions 0.12.3 and older are vulnerable to arbitrary code execution (CVE-2026-46432) due to the application hardcoding `trust_remote_code=True` when loading HuggingFace models, allowing an attacker to execute arbitrary Python code during model initialization.
date: "2026-05-21T17:31:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary code execution
  - huggingface
  - lmdeploy
  - trust_remote_code
vendors:
  - HuggingFace
products:
  - Transformers
  - lmdeploy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1205
    technique_name: Traffic Signaling
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1205
    technique_name: Traffic Signaling
references:
  - https://github.com/advisories/GHSA-m549-qq94-fvhg
rules:
  - title: Detect Suspicious lmdeploy Model Loading
    description: Detects suspicious model paths used with lmdeploy that may indicate an attempt to exploit the hardcoded `trust_remote_code=True` vulnerability (CVE-2026-46432)
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1205
    data_sources:
      - process_creation
      - linux
  - title: Detect lmdeploy Trust Remote Code RCE Proof Marker File Creation
    description: Detects the creation of the marker file used in the lmdeploy trust_remote_code RCE proof of concept (CVE-2026-46432).
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1205
    data_sources:
      - file_event
      - linux
rules_count: 2
---

LMDeploy is vulnerable to arbitrary code execution because it hardcodes `trust_remote_code=True` in multiple HuggingFace model-loading call sites within `lmdeploy/archs.py` and `lmdeploy/utils.py`. This affects calls to `AutoConfig.from_pretrained()`, `PretrainedConfig.get_config_dict()`, and `GenerationConfig.from_pretrained()`. An attacker who can control the `model_path` used by an lmdeploy serving process can point it to an attacker-controlled HuggingFace model repository. When lmdeploy starts and initializes the model, Transformers may download and execute remote Python code from that repository. This vulnerability affects lmdeploy versions 0.12.3 and earlier.

## Attack Chain

1. The attacker gains control over the `model_path` configuration used by lmdeploy.
2. The attacker sets the `model_path` to a malicious HuggingFace repository, such as `attacker-org/malicious-model`.
3. The lmdeploy serving process starts using the attacker-controlled model path via command-line argument (e.g., `lmdeploy serve api_server attacker-org/malicious-model`).
4. During model initialization, lmdeploy calls `AutoConfig.from_pretrained()`, `PretrainedConfig.get_config_dict()`, or `GenerationConfig.from_pretrained()` with `trust_remote_code=True`.
5. The HuggingFace Transformers library downloads Python code from the attacker's repository.
6. Transformers executes the downloaded Python code within the lmdeploy process.
7. The attacker gains arbitrary code execution with the privileges of the lmdeploy serving process.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary Python code during model initialization. The attacker can read files accessible to the lmdeploy process, access environment variables, model provider credentials, cloud credentials, and API keys, modify model-serving behavior, execute operating-system commands, access request data, cause denial of service, and pivot to internal services. This can lead to complete compromise of the lmdeploy server and potentially the wider network.

## Recommendation

*   Apply available patches as provided by the vendor. Upgrade to lmdeploy version 0.13.0 or later.
*   As a workaround, ensure that the `model_path` configuration is sourced from a trusted source.
*   Monitor lmdeploy processes for unexpected file creations in `/tmp` using the marker file path from the provided proof of concept.
*   Deploy the Sigma rule `Detect Suspicious lmdeploy Model Loading` to detect potentially malicious model paths.
