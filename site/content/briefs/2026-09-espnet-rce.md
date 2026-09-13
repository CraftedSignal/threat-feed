---
title: Arbitrary Code Execution in ESPnet via Insecure Deserialization
slug: 2026-09-espnet-rce
description: ESPnet versions prior to 202609 are vulnerable to arbitrary code execution due to the insecure deserialization of pretrained model checkpoints using torch.load with weights_only=False.
date: "2026-09-13T13:25:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:espnet_project:espnet:*:*:*:*:*:*:*:*
vendors:
  - ESPnet
products:
  - ESPnet (< 202609)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: ESPnet before 202609 deserializes pretrained model checkpoints using torch.load with weights_only=False, allowing arbitrary code execution from attacker-supplied files.
    confidence_band: high
cves:
  - id: CVE-2026-90777
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90777
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade ESPnet to version 202609 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-90777 advisory indicates this version resolves the deserialization vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Enforce strict trust policies for model checkpoint sources.
      owner: Security Engineering
      addresses: CVE-2026-90777
      evidence: Source confirms malicious checkpoints enable arbitrary code execution.
---

ESPnet versions prior to 202609 contain a critical vulnerability in the handling of pretrained model checkpoints. The software utilizes the Python 'torch.load' function with the 'weights_only' parameter set to 'False'. By design, 'torch.load' relies on Python's 'pickle' module for deserialization. When 'weights_only' is disabled, the pickle process can instantiate arbitrary objects and execute embedded code within the checkpoint file. An attacker can create a weaponized checkpoint file and trick a user or system into loading it during the initialization or fine-tuning process of an ESPnet model. This flaw allows an attacker to achieve remote code execution in the context of the user or process running the ESPnet toolkit, potentially leading to full system compromise.

## Impact

Successful exploitation allows for arbitrary code execution on systems running ESPnet. Given the nature of machine learning workflows, this poses a risk to research environments, data processing pipelines, and production inference systems where untrusted model checkpoints may be ingested. If exploited, an attacker could gain persistent access, exfiltrate sensitive model data, or pivot within the host network.

## Recommendation

* Upgrade all instances of ESPnet to version 202609 or later immediately to address the insecure deserialization flaw.
* Implement strict validation and provenance checks for all pretrained model checkpoints before loading them into the ESPnet framework.
* Execute machine learning model processing within isolated containers or restricted environments to minimize the impact of potential command execution.
* Monitor the Python process execution logs for unexpected child processes spawned by model initialization scripts.
