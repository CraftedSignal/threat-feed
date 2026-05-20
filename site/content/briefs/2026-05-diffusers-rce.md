---
title: Diffusers TOCTOU Vulnerability Leads to Remote Code Execution
slug: 2026-05-diffusers-rce
description: A Time-of-Check Time-of-Use (TOCTOU) vulnerability in the `diffusers` package allows arbitrary code execution via a race condition when loading pipelines from the Hugging Face Hub, bypassing trust checks.
date: "2026-05-20T15:32:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - toctou
  - rce
  - huggingface
vendors:
  - Hugging Face
products:
  - diffusers (< 0.38.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-7wx4-6vff-v64p
  - CVE-2026-45804
rules:
  - title: Detect Diffusers from_pretrained without trust_remote_code
    description: Detects calls to DiffusionPipeline.from_pretrained without explicit trust_remote_code, which may indicate a potential TOCTOU exploit attempt targeting CVE-2026-45804.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Connection from Diffusers Process
    description: Detects network connections initiated by processes related to the diffusers library, potentially indicating command and control activity after CVE-2026-45804 exploitation.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A TOCTOU vulnerability exists in the `diffusers` package (versions prior to 0.38.0), a library used for diffusion models. The vulnerability resides within the `DiffusionPipeline.from_pretrained` function, which is responsible for loading pipelines from the Hugging Face Hub. This function has a `trust_remote_code` guard intended to prevent the execution of untrusted code from custom pipelines. However, a race condition between two HTTP calls (`hf_hub_download` and `snapshot_download`) allows an attacker to introduce malicious code into the repository between the calls, effectively bypassing the trust check and enabling remote code execution. This occurs because the vulnerability allows arbitrary code to be loaded through the custom pipeline flow from a Hub repo, even without explicitly passing `custom_pipeline` or `trust_remote_code` arguments.

## Attack Chain

1. An attacker creates a Hugging Face Hub repository with a `model_index.json` file containing a plain string `_class_name` value, indicating no custom pipeline code.
2. A user attempts to load the pipeline using `DiffusionPipeline.from_pretrained("attacker/repo")`.
3. The `hf_hub_download` function fetches the `model_index.json` file (commit A) and the trust check passes because no custom pipeline is detected.
4. Before the `snapshot_download` function is called, the attacker pushes a new commit (commit B) to the repository, modifying the `model_index.json` file to use a list `_class_name` and adding a malicious `pipeline.py` file.
5. The `snapshot_download` function fetches commit B, including the malicious `pipeline.py` file.
6. The `_resolve_custom_pipeline_and_cls` function reads the updated `model_index.json` and resolves the custom pipeline to the local path of the `pipeline.py` file.
7. The `_get_pipeline_class` function imports the malicious `pipeline.py` file without any further trust checks.
8. The malicious code within `pipeline.py` is executed, resulting in arbitrary code execution on the user's machine.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the victim's machine. The vulnerability is a silent RCE meaning that the from_pretrained call succeeds and returns a fully functional pipeline even when malicious code has been injected. This could lead to data exfiltration, system compromise, or other malicious activities. The impact is significant as it undermines the trust mechanisms designed to protect users from running untrusted code.

## Recommendation

*   Upgrade to `diffusers` version 0.38.0 or later to patch the vulnerability.
*   When using `DiffusionPipeline.from_pretrained`, pin the `revision` argument to a specific commit hash to avoid race conditions, as described in the overview.
*   Deploy the Sigma rule "Detect Diffusers from_pretrained with trust_remote_code" to detect potential exploitation attempts by identifying calls to `DiffusionPipeline.from_pretrained` without explicit trust settings.
*   Monitor network connections for unexpected outbound traffic originating from processes associated with the `diffusers` library, using the network connection Sigma rule in this brief to identify potential command and control activity.
