---
title: Remote Code Execution in Unsloth Zoo via Model Configuration
slug: 2026-09-unsloth-rce
description: Unsloth Zoo and Unsloth are vulnerable to remote code execution due to improper input validation in the model-loading compile path, allowing arbitrary Python code execution via malicious config.json files.
date: "2026-09-28T16:21:11Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Unsloth
products:
  - Unsloth Zoo (2025.9.9-2026.8.13)
  - Unsloth (2025.9.9-2026.8.19)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can embed a newline in a nested model_type value within a malicious model's config.json to terminate the generated import statement and execute arbitrary Python code via exec() in unsloth_compile_transformers().
    confidence_band: high
cves:
  - id: CVE-2026-93348
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93348
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Unsloth Zoo to 2026.8.14 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-93348 patching requirement
  mitigation_plan:
    - priority: immediate
      action: Enforce strict schema validation on all incoming model config.json files
      owner: IT Operations
      addresses: CVE-2026-93348
      evidence: Vulnerability caused by lack of character allowlist
---

Unsloth Zoo versions 2025.9.9 before 2026.8.14 and Unsloth versions 2025.9.9 through 2026.8.19 contain a critical code injection vulnerability. The flaw exists within the `get_transformers_model_type()` function located in `hf_utils.py`, which is responsible for collecting `model_type` values from nested model configurations. The function fails to enforce a character allowlist, permitting newlines and arbitrary Python source code to pass through normalization.

An attacker can supply a malicious `config.json` file where the `model_type` field contains an injected newline character followed by arbitrary Python statements. When the model is loaded for training or inference, `unsloth_compile_transformers()` processes this configuration and passes the malicious input into an `exec()` call. This results in arbitrary code execution with the permissions of the user or service account performing the model load. This vulnerability impacts environments that load untrusted or externally sourced model configurations into Unsloth-based pipelines.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user running the Unsloth framework. This could lead to full system compromise, exfiltration of sensitive model data, or persistence on the server hosting the training or inference environment.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Upgrade Unsloth Zoo to version 2026.8.14 or later, and Unsloth to versions beyond 2026.8.19, to incorporate the necessary input sanitization.
- Implement file integrity monitoring or scanning on model repositories to detect suspicious characters (e.g., newlines, `import`, `exec`, `eval`) within `config.json` files before they are processed by the training or inference pipeline.
- Run model-loading processes in isolated, low-privilege containers or sandboxes to limit the impact of potential RCE in the `unsloth_compile_transformers()` function.
