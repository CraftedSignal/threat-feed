---
title: Remote Code Execution in Xinference via Unsafe Model Loading
slug: 2026-08-xinference-rce
description: Xinference versions prior to 2.12.0 are vulnerable to remote code execution because they unconditionally enable 'trust_remote_code=True' when loading models, allowing attackers to execute arbitrary Python code via crafted model configurations.
date: "2026-08-24T16:02:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - vulnerability
  - ai-security
vendors:
  - Xinference
products:
  - Xinference (< 2.12.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The server reaches _auto_detect_type and then AutoTokenizer.from_pretrained, which imports and executes Python declared by the model directory's own tokenizer_config.json auto_map.
    confidence_band: high
cves:
  - id: CVE-2026-76841
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76841
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Xinference to version 2.12.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-76841 remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the model registration API
      owner: IT Operations
      addresses: CVE-2026-76841
      evidence: Source states that a caller with model launch access can supply an arbitrary model path to trigger the exploit.
---

Xinference versions prior to 2.12.0 contain a critical remote code execution (RCE) vulnerability (CVE-2026-76841) rooted in the insecure implementation of Hugging Face Transformers model loading. The application contains six distinct loader call sites that pass 'trust_remote_code=True' to the underlying Transformers library, either as a hardcoded literal or a default configuration. 

This implementation allows an attacker with model launch access to register a custom model type and supply a malicious model path. During the model loading sequence, the server invokes 'AutoTokenizer.from_pretrained'. If an attacker provides a 'tokenizer_config.json' file containing an 'auto_map' entry, the server will automatically import and execute arbitrary Python code defined within the model directory. This code executes with the full privileges of the Xinference worker process. Version 2.12.0 mitigates this issue by introducing the 'XINFERENCE_TRUST_REMOTE_CODE' setting and requiring explicit enablement to permit remote code execution for non-bundled models.

## Impact

An attacker exploiting this vulnerability achieves remote code execution in the context of the worker process. This can lead to full compromise of the hosting server, sensitive data exfiltration, or lateral movement within the environment. This vulnerability affects any deployment of Xinference prior to version 2.12.0 that allows untrusted users to launch or register new model paths.

## Recommendation

* Immediately upgrade all instances of Xinference to version 2.12.0 or later to ensure the 'trust_remote_code' functionality is gated by configuration.
* Audit current model registration logs for the registration of arbitrary model paths or custom model types by unauthorized users.
* Restrict model registration and launch capabilities to trusted administrators or authenticated service identities within the infrastructure.
