---
title: 'Stanza: Remote Code Execution via Unsafe Pickle Deserialization in Model Loaders'
slug: 2026-06-stanza-rce
description: Stanza, an NLP library, is vulnerable to remote code execution (CVE-2026-54499) due to an unsafe fallback mechanism when loading PyTorch model files, allowing an attacker who can place a malicious pretrain or model file to achieve arbitrary code execution on systems processing NLP pipelines, leading to credential theft, backdoors, data exfiltration, and lateral movement.
date: "2026-06-19T19:36:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - deserialization
  - rce
  - python
  - pytorch
  - machine-learning
  - supply-chain
  - cwe-502
  - nlp
  - ghsa
vendors:
  - Stanford NLP
  - PyTorch
products:
  - Stanza (<= 1.12.1)
  - PyTorch (< 2.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-v5jw-96jm-7h2c
rules:
  - title: Detects CVE-2026-54499 Exploitation — Python Spawning Suspicious Child Process (Linux)
    description: Detects CVE-2026-54499 exploitation resulting in Python spawning a suspicious child process like a shell, or common downloading/execution tools on Linux systems.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
  - title: Detects CVE-2026-54499 Exploitation — Python Creating Suspicious Files in /tmp (Linux)
    description: Detects CVE-2026-54499 exploitation where Python writes suspicious files (e.g., executables, scripts, or specific sentinel files used in PoCs) to the /tmp directory on Linux systems.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.006
      - T1106
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Stanza Natural Language Processing (NLP) library, specifically version 1.12.0 and earlier, is susceptible to an arbitrary code execution vulnerability (CVE-2026-54499) stemming from unsafe deserialization. When attempting to load PyTorch checkpoint files, Stanza's `torch.load` implementation initially uses a `weights_only=True` flag for safety. However, if this safe load raises a `pickle.UnpicklingError` (a condition controllable by an attacker via a specially crafted `.pt` file containing an unsupported pickle global), Stanza immediately falls back to reloading the *same attacker-controlled file* with `weights_only=False`. This completely bypasses PyTorch's safety mechanisms, invoking Python's full pickle deserializer, which can execute any `__reduce__` method embedded in the malicious file. The vulnerability affects any user, researcher, or NLP service loading Stanza models from untrusted or compromised sources, enabling full system compromise.

## Attack Chain

1.  **Attacker Crafts Malicious Model**: An attacker prepares a malicious PyTorch `.pt` file, embedding arbitrary Python code in its `__reduce__` method and including at least one unsupported pickle global to force an `UnpicklingError` during safe loading.
2.  **Model Placement/Distribution**: The attacker places this malicious `.pt` file on a system or repository where it can be loaded by a victim (e.g., via supply-chain compromise of a model repository like HuggingFace, poisoning a shared model cache, or distributing it through third-party fine-tuning hubs).
3.  **Victim Initiates Model Load**: A victim's application, CI/CD pipeline, or research environment uses the Stanza API (`stanza.Pipeline()`, `load_pretrain()`) to load a pretrain or model file, unknowingly targeting the malicious `.pt` file.
4.  **Initial Safe Load Attempt**: Stanza's internal `Pretrain.load()` function attempts to load the `.pt` file using `torch.load(..., weights_only=True)`.
5.  **UnpicklingError Triggered**: Due to the attacker-controlled unsupported pickle global, PyTorch raises a `pickle.UnpicklingError` as intended by its `weights_only=True` safety feature.
6.  **Unsafe Fallback Invoked**: Stanza's vulnerable `try...except` block catches the `UnpicklingError` and immediately reloads the *same malicious file* using `torch.load(..., weights_only=False)`.
7.  **Arbitrary Code Execution**: Python's full pickle deserializer executes the attacker's arbitrary code embedded within the malicious `.pt` file's `__reduce__` method, with the privileges of the Stanza process.
8.  **Impact Achieved**: The attacker's payload executes, leading to consequences such as credential theft (HuggingFace tokens, cloud IAM keys), installation of persistent backdoors, data exfiltration, or lateral movement within the victim's infrastructure.

## Impact

This vulnerability, classified as CWE-502 (Deserialization of Untrusted Data), has severe consequences for any user, researcher, CI/CD pipeline, or production NLP service that loads a Stanza model pretrain file from sources not under exclusive cryptographic control. Attackers who can place a malicious `.pt` file can achieve arbitrary code execution with the full privileges of the process running `stanza.Pipeline()`. This can be a developer workstation, a Jupyter notebook server, or a GPU training node, potentially leading to credential theft (e.g., HuggingFace tokens, cloud IAM keys from environment variables), persistent backdoors, data exfiltration, and lateral movement in multi-tenant training infrastructure. The vulnerability affects Stanza versions up to and including 1.12.1.

## Recommendation

*   Upgrade Stanza to a patched version immediately (version 1.12.2 or higher) to mitigate CVE-2026-54499, which removes the unsafe fallback for `pickle.UnpicklingError`.
*   Review and ensure all Stanza loaders, including those in `stanza/models/common/pretrain.py`, `stanza/models/coref/model.py`, `stanza/models/classifiers/trainer.py`, and `stanza/models/constituency/base_trainer.py`, have the unsafe fallback removed.
*   Deploy the provided Sigma rules to detect suspicious process creation and file modifications indicative of successful exploitation of CVE-2026-54499.
*   Enable comprehensive logging for `process_creation` and `file_event` on Linux and Windows systems where Stanza is used.
