---
title: Unsafe Deserialization Vulnerability in docTR
slug: 2026-10-doctr-deserialization
description: docTR versions through 1.1.0 are vulnerable to arbitrary code execution via unsafe deserialization of pickle payloads within the load_pretrained_params() function.
date: "2026-10-19T18:08:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mindee:doctr:*:*:*:*:*:*:*:*
tags:
  - deserialization
  - remote-code-execution
  - python
  - supply-chain
vendors:
  - Mindee
products:
  - docTR (<= 1.1.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers who control a local or URL-supplied checkpoint can embed a malicious pickle payload to execute Python code with the loading process privileges.
    confidence_band: high
cves:
  - id: CVE-2026-112304
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112304
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Upgrade docTR to 2.6 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-112304
  mitigation_plan:
    - priority: immediate
      action: Upgrade PyTorch to 2.6 or later to mitigate unsafe deserialization defaults.
      owner: IT Operations
      addresses: CVE-2026-112304
      evidence: Source notes PyTorch releases before 2.6 are susceptible to this payload type.
---

Mindee docTR (Document Text Recognition) versions through 1.1.0 contain a critical unsafe deserialization vulnerability identified as CVE-2026-112304. The vulnerability exists within the `load_pretrained_params()` function, which invokes `torch.load` to process model checkpoints. By default, the library fails to set the `weights_only=True` parameter, which is a required security configuration for loading untrusted PyTorch models. 

An attacker who can provide a malicious checkpoint file - either via local storage or a remote URL - can embed a malicious pickle payload within the file. When `load_pretrained_params()` processes this file, the underlying PyTorch mechanism (on versions prior to 2.6) will deserialize the payload, resulting in arbitrary Python code execution under the security context of the user or service running the docTR library. This vulnerability is significant for environments where document processing pipelines ingest user-supplied model files or rely on potentially compromised remote storage.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve arbitrary code execution on the system running the docTR library. This could lead to a full compromise of the application server, data exfiltration from the processing environment, or lateral movement within the network. The scope affects any application utilizing docTR version 1.1.0 or earlier for OCR tasks.

## Recommendation

* Update docTR to a version that enforces `weights_only=True` in `load_pretrained_params()`.
* If patching is not immediately feasible, audit the code to ensure `load_pretrained_params()` is only ever called with trusted, verified local model files.
* Verify the PyTorch version in the environment and ensure it is updated to 2.6 or later to benefit from improved default deserialization safety.
* Implement file integrity monitoring on any directory where model checkpoints are stored to detect unauthorized modifications.
