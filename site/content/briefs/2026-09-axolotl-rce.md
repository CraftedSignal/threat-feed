---
title: Remote Code Execution in Axolotl via trust_remote_code Bypass
slug: 2026-09-axolotl-rce
description: Axolotl versions through 0.18.0 contain a remote code execution vulnerability where an insecure default configuration allows attackers to bypass security guards and execute arbitrary Python code.
date: "2026-09-05T11:31:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:axolotl:axolotl:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - machine-learning
  - supply-chain
vendors:
  - Axolotl
products:
  - Axolotl (<= 0.18.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can execute arbitrary Python code by crafting a malicious Hugging Face model repository selected as base_model.
    confidence_band: high
cves:
  - id: CVE-2026-86169
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86169
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Axolotl to a version above 0.18.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-86169
  mitigation_plan:
    - priority: immediate
      action: Restrict egress traffic from ML training clusters
      owner: IT Operations
      addresses: CVE-2026-86169
      evidence: Vulnerability allows remote code execution via malicious Hugging Face repository load.
---

Axolotl versions through 0.18.0 are vulnerable to remote code execution (CVE-2026-86169) due to an insecure default configuration within the multipack patch path. The application fails to properly restrict the trust_remote_code parameter, which defaults to None rather than the intended False. This oversight enables a security guard bypass, allowing the application to load code from untrusted sources. An attacker can leverage this flaw by providing a crafted Hugging Face model repository as the base_model. When Axolotl executes the AutoModelForCausalLM.from_pretrained function, the malicious model is loaded with hardcoded trust_remote_code=True, resulting in the execution of arbitrary Python code within the host environment. This vulnerability is significant for organizations using Axolotl for fine-tuning Large Language Models, as it allows for full compromise of the training infrastructure.

## Attack Chain

1. Attacker creates a malicious Hugging Face model repository containing arbitrary Python code.
2. Attacker configures the target Axolotl instance to use the malicious model as the base_model.
3. Axolotl triggers the multipack patch path during the training process initialization.
4. The application logic fails to override trust_remote_code=None, defaulting to an insecure state.
5. Axolotl calls AutoModelForCausalLM.from_pretrained to load the specified base_model.
6. The underlying Hugging Face transformer library executes the embedded Python code from the repository.
7. Attacker achieves remote code execution within the context of the user or service account running the Axolotl training job.

## Impact

Successful exploitation allows for arbitrary code execution on the system running Axolotl. This can lead to total system compromise, exfiltration of sensitive model training data, theft of API tokens, or further lateral movement within the network. Sectors utilizing automated AI/ML pipelines and fine-tuning frameworks are primary targets.

## Recommendation

Update Axolotl to a version beyond 0.18.0 that properly enforces trust_remote_code=False. In the interim, implement strict egress filtering on training nodes to prevent model-loading infrastructure from reaching unauthorized or untrusted repositories. Audit all model configuration files for the use of external repositories.

## Impact
Impact includes unauthorized code execution on the training server.
