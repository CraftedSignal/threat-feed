---
title: Arbitrary Code Execution in Fujitsu OneCompression Library
slug: 2026-08-fujitsu-onecompression-rce
description: Fujitsu OneCompression library version 1.2.0 is vulnerable to arbitrary code execution via unsafe deserialization in the QuantizedModelLoader component.
date: "2026-08-12T18:49:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - deserialization
  - rce
  - supply-chain
vendors:
  - Fujitsu
products:
  - OneCompression (1.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Attackers can embed malicious __reduce__ methods in a crafted model checkpoint to execute arbitrary Python code, including system commands, when the library loads the file from a caller-selected model directory.
    confidence_band: high
cves:
  - id: CVE-2026-73325
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73325
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Review inventory for usage of OneCompression 1.2.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-73325 impact analysis
  mitigation_plan:
    - priority: immediate
      action: Upgrade or restrict loading of untrusted .pt files
      owner: IT Operations
      addresses: CVE-2026-73325
      evidence: Vulnerability requires untrusted input for exploitation
---

Fujitsu Research's OneCompression library version 1.2.0 contains a critical unsafe deserialization vulnerability, tracked as CVE-2026-73325. The flaw exists within the QuantizedModelLoader.load_quantized_model_pt() function, which unconditionally invokes the torch.load() method with the weights_only parameter set to False. By setting weights_only=False, the underlying PyTorch loader utilizes Python's pickle module for deserializing checkpoint files. 

An attacker can supply a maliciously crafted model.pt checkpoint file containing an embedded __reduce__ method. When the library processes this file, it triggers the execution of the attacker's Python code within the context of the host process. This vulnerability allows for arbitrary command execution on systems leveraging this library to load model checkpoints, posing a high risk for machine learning pipelines or applications that ingest externally provided model files.

## Impact

Successful exploitation of this vulnerability leads to arbitrary code execution on systems running applications that utilize OneCompression version 1.2.0. This can result in full system compromise, data exfiltration, or persistence on the affected host. Any environment processing untrusted model files from external sources is at significant risk.

## Recommendation

- Update the OneCompression library to the latest version once a patch is provided by the vendor.
- Implement strict input validation for all model checkpoint files to ensure they originate from trusted, verified sources.
- Monitor application environments for the execution of unexpected processes originating from processes that utilize the OneCompression library.
- Audit Python applications utilizing PyTorch to ensure torch.load() is used with weights_only=True whenever possible to mitigate deserialization risks globally.
