---
title: Remote Code Execution Vulnerability in PyTorch Lightning via Malicious Checkpoint Files (CVE-2026-58659)
slug: 2026-07-pytorch-lightning-rce
description: A remote code execution vulnerability, CVE-2026-58659, exists in PyTorch Lightning through version 2.6.5, allowing attackers to craft malicious checkpoint files that execute arbitrary code by exploiting a flaw in the `_load_state` function when `LightningModule.load_from_checkpoint` is called.
date: "2026-07-15T18:22:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - vulnerability
  - python
  - pytorch
vendors:
  - Lightning-AI
products:
  - PyTorch Lightning (through 2.6.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can craft malicious checkpoint files that bypass weights_only=True protections to execute arbitrary code when LightningModule.load_from_checkpoint is called.
    confidence_band: high
cves:
  - id: CVE-2026-58659
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58659
  - https://github.com/Lightning-AI/pytorch-lightning/commit/d710d689510d50e800f53b3cd773cbca20b1f86f
  - https://github.com/Lightning-AI/pytorch-lightning/issues/21822
  - https://github.com/Lightning-AI/pytorch-lightning/pull/21832
  - https://www.vulncheck.com/advisories/pytorch-lightning-arbitrary-code-execution-via-instantiator-hyperparameter
iocs:
  - type: hash_sha1
    value: d710d689510d50e800f53b3cd773cbca20b1f86f
ioc_counts:
  hash_sha1: 1
---

A critical remote code execution (RCE) vulnerability, tracked as CVE-2026-58659, has been identified in PyTorch Lightning versions up to and including 2.6.5. This flaw resides within the `_load_state` function, which is responsible for loading model states from checkpoint files. Attackers can exploit this by crafting malicious checkpoint files containing specially crafted `_instantiator` hyperparameters. When a victim or automated process loads such a malicious file using `LightningModule.load_from_checkpoint()`, the `_load_state` function improperly imports and executes attacker-controlled module names, leading to arbitrary code execution. This bypasses the `weights_only=True` protection, enabling full system compromise. The vulnerability was fixed in commit `d710d68` and was published by NVD on July 15, 2026. This vulnerability has a CVSS v3.1 Base Score of 7.8, indicating a high severity risk for users of affected versions.

## Attack Chain

1. Attacker crafts a malicious PyTorch Lightning checkpoint file (`.ckpt` or similar) designed to exploit CVE-2026-58659.
2. The malicious checkpoint file is embedded with attacker-controlled module names within its `_instantiator` hyperparameters.
3. Attacker delivers the malicious checkpoint file to a victim's system, potentially via email (phishing), untrusted download links, or by compromising a data repository.
4. A user or automated process on the victim's system loads the malicious checkpoint file using the `LightningModule.load_from_checkpoint()` function.
5. During the loading process, the vulnerable `_load_state` function is invoked.
6. The `_load_state` function attempts to process the `_instantiator` hyperparameters, importing and executing the attacker-controlled module names.
7. The `weights_only=True` protection mechanism within PyTorch Lightning is bypassed due to the nature of this vulnerability.
8. Arbitrary code embedded or referenced by the attacker within the malicious checkpoint file is executed on the victim's system, leading to remote code execution.

## Impact

Successful exploitation of CVE-2026-58659 allows an attacker to achieve arbitrary code execution on the system where the malicious PyTorch Lightning checkpoint file is processed. This can lead to a complete compromise of the affected system, allowing attackers to steal sensitive data, install further malware, modify system configurations, or disrupt operations. While no specific victim organizations or sectors are detailed in the advisory, any environment utilizing vulnerable PyTorch Lightning versions for model training or inference, particularly those loading checkpoint files from untrusted sources, is at risk. The direct consequence is a loss of confidentiality, integrity, and availability of the compromised system and potentially connected resources.

## Recommendation

* Immediately update all PyTorch Lightning installations to a version beyond 2.6.5, incorporating the fix from commit `d710d689510d50e800f53b3cd773cbca20b1f86f`.
* Educate users on the risks of loading `.ckpt` or similar PyTorch Lightning checkpoint files from untrusted or unverified sources, as described in the attack chain.
* Implement strict access controls and validation for PyTorch Lightning checkpoint files, ensuring only trusted and signed models are loaded into production environments.
* Monitor systems for unusual process execution or network activity originating from applications loading PyTorch Lightning models, which could indicate arbitrary code execution as described in the attack chain.
