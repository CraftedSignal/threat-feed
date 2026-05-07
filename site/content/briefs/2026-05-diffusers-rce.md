---
title: Diffusers trust_remote_code Bypass Leads to Remote Code Execution
slug: 2026-05-diffusers-rce
description: A `trust_remote_code` bypass vulnerability exists in the `DiffusionPipeline.from_pretrained` function of the diffusers library, allowing for arbitrary remote code execution when using `custom_pipeline` and local custom components, even when `trust_remote_code=False` is set.
date: "2026-05-07T05:31:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - diffusers
  - trust_remote_code
vendors:
  - Hugging Face
products:
  - diffusers (< 0.38.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1205
    technique_name: Traffic Signaling
references:
  - https://github.com/advisories/GHSA-98h9-4798-4q5v
  - https://github.com/huggingface/diffusers/pull/13448
  - https://github.com/huggingface/diffusers/issues/13446
  - https://github.com/huggingface/diffusers/releases/tag/v0.38.0
  - https://cwe.mitre.org/data/definitions/94.html
rules:
  - title: Detect Python Execution from Suspicious Paths
    description: Detects the execution of Python files from world-writable directories, which may indicate a trust_remote_code bypass attack
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation in Diffusers Cache Directories
    description: Detects the creation of suspicious files (e.g., *.py) in Diffusers cache directories, indicating a potential `trust_remote_code` bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - linux
  - title: Detect Diffusers Loading Remote Pipelines with Trust Disabled
    description: Detects the loading of remote custom pipelines in Diffusers while trust_remote_code is disabled or not explicitly enabled. This can indicate a potential vulnerability exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A `trust_remote_code` bypass in `DiffusionPipeline.from_pretrained` allows arbitrary remote code execution despite the user passing `trust_remote_code=False` (or omitting it, which is the default). The vulnerability, impacting diffusers versions before 0.38.0, stems from the `trust_remote_code` gate being implemented inside `DiffusionPipeline.download()` rather than at the actual dynamic-module load site. This allows for bypasses using cross-repo `custom_pipeline`, local snapshots with Hub `custom_pipeline`, and local snapshots with custom components. Successful exploitation results in silent remote code execution on the victim's machine, affecting anyone calling `DiffusionPipeline.from_pretrained` with custom pipelines. The vulnerability is tracked as CVE-2026-44513.

## Attack Chain

1. A user calls `DiffusionPipeline.from_pretrained` with a malicious `custom_pipeline` pointing to an attacker's repository (repoB) while setting `trust_remote_code=False`.
2. The `DiffusionPipeline.download()` function is invoked, but the trust check is performed against the primary repository (repoA) instead of the attacker's repository (repoB).
3. Alternatively, the user calls `DiffusionPipeline.from_pretrained` with a local snapshot directory and a malicious `custom_pipeline` pointing to an attacker's repository. The local-path branch bypasses the `download()` function, thus skipping the `trust_remote_code` gate.
4. As another alternative, the user calls `DiffusionPipeline.from_pretrained` with a local snapshot directory containing custom component files (e.g., `unet/my_unet_model.py`) referenced from `model_index.json`. The local path bypasses `download()`.
5. The attacker's `pipeline.py` or custom component files are loaded as dynamic modules.
6. The attacker's code is executed, granting the attacker arbitrary code execution privileges on the victim's machine.
7. The attacker can then perform various malicious activities, such as installing malware, stealing data, or compromising the system.

## Impact

Successful exploitation of this vulnerability allows for arbitrary remote code execution on the victim's machine. This could lead to complete system compromise, data theft, or other malicious activities. All users of diffusers versions before 0.38.0 who call `DiffusionPipeline.from_pretrained` with custom pipelines are potentially affected.

## Recommendation

*   Upgrade to diffusers version 0.38.0 or later to remediate the vulnerability. The fix moves the `trust_remote_code` gate to `get_cached_module_file` in `src/diffusers/utils/dynamic_modules_utils.py` ([https://github.com/huggingface/diffusers/pull/13448](https://github.com/huggingface/diffusers/pull/13448)).
*   If upgrading is not immediately possible, only call `from_pretrained` with `pretrained_model_name_or_path`, `custom_pipeline`, and local snapshot directories from fully trusted sources that have been audited.
*   If a local snapshot is used, inspect it for unexpected `*.py` files, especially under component subdirectories (`unet/`, `scheduler/`, etc.) and at the snapshot root before calling `from_pretrained`.
*   Deploy the Sigma rule to detect execution of unexpected python files.
