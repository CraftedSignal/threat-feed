---
title: Hugging Face Diffusers Remote Code Execution via None.py
slug: 2026-05-diffusers-rce
description: A remote code execution vulnerability exists in Hugging Face diffusers versions prior to 0.38.0 allowing arbitrary code execution through the `custom_pipeline` flow via a `None.py` file in a Hugging Face Hub repository, bypassing trust checks.
date: "2026-05-07T02:24:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - huggingface
  - diffusers
vendors:
  - Hugging Face
products:
  - diffusers (< 0.38.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-j7w6-vpvq-j3gm
  - https://github.com/huggingface/diffusers/pull/13448
rules:
  - title: Detect Diffusers None.py RCE
    description: Detects the execution of None.py as part of a diffusers pipeline, indicating a potential RCE vulnerability exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - process_creation
      - windows
  - title: Detect Diffusers Dynamic Module Load from Unusual Location
    description: Detects loading of python modules from temporary directories, which can be indicative of malicious code execution in Diffusers
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - image_load
      - windows
rules_count: 2
---

A remote code execution (RCE) vulnerability has been identified in Hugging Face diffusers library versions prior to 0.38.0. This flaw stems from insufficient validation in the `DiffusionPipeline.from_pretrained` function when loading custom pipelines from the Hugging Face Hub. By including a file named `None.py` in a model repository, an attacker can bypass the `trust_remote_code` check, leading to arbitrary code execution when a user loads the model. This vulnerability allows attackers to execute malicious code on a user's machine simply by having them load a seemingly benign model, without requiring any explicit trust or custom pipeline specifications. The vulnerability was introduced due to a flaw in how the library resolves custom pipeline paths, leading to the unintentional inclusion of `None.py` as a valid custom pipeline file.

## Attack Chain

1.  Attacker creates a Hugging Face Hub repository containing a malicious `None.py` file, alongside other model files and a `model_index.json` configuration file.
2.  The `None.py` file contains malicious code disguised within a class that inherits from `DiffusionPipeline`, such as shadowing `FluxPipeline` and executing arbitrary commands like writing a file to `/tmp/pwned`.
3.  A victim user attempts to load the model using `DiffusionPipeline.from_pretrained('attacker/malicious-repo')`.
4.  The `from_pretrained` function calls `DiffusionPipeline.download()`, which ordinarily checks for `trust_remote_code` when a custom pipeline is specified.
5.  Due to a flaw, `_resolve_custom_pipeline_and_cls` resolves `custom_pipeline` to `None.py` if the file exists in the repo, bypassing the `trust_remote_code` check because the check evaluated `custom_pipeline is None -> False`.
6.  The `_get_pipeline_class` function is then called with the resolved `None.py` path, loading and executing the malicious code within the file.
7.  The malicious code executes, performing actions such as creating a file, establishing a reverse shell, or exfiltrating data.
8.  The pipeline is instantiated and appears functional to the user, masking the underlying malicious activity.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve remote code execution on the victim's machine. This can lead to complete system compromise, data theft, or deployment of further malicious payloads. The vulnerability affects any user who loads a malicious model from the Hugging Face Hub using the vulnerable versions of the diffusers library.  The impact is significant because it requires no user interaction beyond loading a model, making it easy to exploit at scale.

## Recommendation

*   Upgrade the `diffusers` package to version 0.38.0 or later using `pip install --upgrade "diffusers>=0.38.0"` to patch the vulnerability as recommended by the vendor.
*   Implement the provided Sigma rule `Detect Diffusers None.py RCE` to detect the execution of `None.py` within the diffusers library.
*   Prioritize scanning Hugging Face Hub repositories before use, looking for unexpected `*.py` files, especially `None.py`, using manual code review or automated tools.
*   As a workaround, only load models from trusted sources, and inspect local snapshots for unexpected `*.py` files as described in the advisory.
