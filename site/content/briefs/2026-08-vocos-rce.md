---
title: Arbitrary Code Execution in Vocos via Unrestricted Class Instantiation
slug: 2026-08-vocos-rce
description: The Vocos library contains an arbitrary code execution vulnerability in its configuration loading process that allows attackers to execute arbitrary Python callables when loading models from untrusted repositories.
date: "2026-08-25T18:10:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-code-execution
  - machine-learning
  - supply-chain
vendors:
  - Vocos
products:
  - Vocos
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: The instantiate_class function imports the module with __import__, resolves the attribute with getattr, and calls the result as args_class(*args, **kwargs).
    confidence_band: high
cves:
  - id: CVE-2026-79784
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79784
action_plan:
  priority: elevated
  owners:
    - SOC
    - DevSecOps
  immediate_actions:
    - action: Review and restrict model sourcing to internal, vetted registry locations.
      owner: DevSecOps
      due: 48h
      evidence: CVE-2026-79784 exposes model loading to arbitrary code execution.
  mitigation_plan:
    - priority: immediate
      action: Implement strict allowlisting for domains used for model downloads.
      owner: IT Operations
      addresses: CVE-2026-79784
      evidence: NVD vulnerability report.
---

The Vocos library, primarily used for audio synthesis tasks, contains a critical arbitrary code execution vulnerability (CVE-2026-79784) within its model loading infrastructure. The vulnerability exists in the `instantiate_class` function located in `vocos/pretrained.py`. This function reads a `class_path` from a configuration file, dynamically imports the specified module using `__import__`, retrieves the attribute via `getattr`, and executes the resulting callable using arguments provided in the configuration's `init_args` mapping.

Crucially, the library fails to implement an allowlist to restrict which classes or functions can be instantiated. The `Vocos.from_pretrained` method allows users to load models from Hugging Face repositories, which triggers the download of a `config.yaml` file. Because this file is passed directly to the vulnerable `from_hparams` method, an attacker who controls a Hugging Face repository can point the configuration to any importable Python callable on the victim's system, resulting in arbitrary code execution during the model loading process.

## Impact

Successful exploitation allows for full arbitrary code execution under the privileges of the Python process loading the malicious model. This impacts data scientists and machine learning engineers using Vocos to load models from third-party or public repositories. Attackers can leverage this to gain persistence or access sensitive data within the environment where the model is being loaded.

## Recommendation

- Audit all internal model loading workflows to ensure that Vocos models are only loaded from trusted, verified sources.
- Implement strict network egress filtering for servers processing machine learning models to prevent unauthorized downloads from untrusted Hugging Face repositories.
- If possible, wrap the Vocos model loading process in a sandboxed or containerized environment with restricted filesystem and network access.
- Monitor for Python processes using the `vocos` library that are initiating unexpected outbound network connections, particularly to unknown or non-official Hugging Face repository domains.
