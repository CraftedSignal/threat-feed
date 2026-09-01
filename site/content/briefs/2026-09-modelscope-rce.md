---
title: Arbitrary Code Execution in ModelScope via Insecure PyYAML Parsing
slug: 2026-09-modelscope-rce
description: ModelScope insecurely utilizes the unsafe yaml.Loader to parse model configuration files, allowing an attacker to achieve arbitrary code execution by supplying a poisoned repository containing malicious Python object construction tags.
date: "2026-09-01T17:07:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:modelscope:modelscope:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - supply-chain
vendors:
  - ModelScope
products:
  - ModelScope
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: Attackers can craft malicious model repositories with poisoned configuration files that execute code when loaded by users.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: ModelScope uses PyYAML's unsafe yaml.Loader to parse model configuration files, allowing arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-84202
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84202
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update ModelScope library to the latest patched version
      owner: IT Operations
      due: 48h
      evidence: Source identifies vulnerability in ModelScope configuration parsing
  mitigation_plan:
    - priority: immediate
      action: Enforce the use of yaml.SafeLoader within local code wrappers if direct library updates are delayed
      owner: Software Engineering
      addresses: CVE-2026-84202
      evidence: Source identifies use of unsafe yaml.Loader as root cause
---

ModelScope is a machine learning model library that, in affected versions, improperly handles model configuration files. The vulnerability arises from the use of PyYAML's `yaml.Loader` (often referred to as the unsafe loader) to deserialize configuration files. By crafting a model repository that includes a maliciously formatted configuration file containing specific Python object construction tags (e.g., `!!python/object/apply`), an attacker can trigger arbitrary code execution within the context of the user or system loading the model. This impact is significant for organizations relying on ModelScope to pull and execute machine learning models from external or potentially untrusted repositories, as the mere act of loading a configuration file becomes a primary vector for host compromise.

## Impact

Successful exploitation allows an attacker to execute arbitrary code with the privileges of the process running the ModelScope framework. This can lead to full host compromise, exfiltration of sensitive data, or lateral movement within the network. Users of the library who automatically ingest models from public or unvetted sources are at the highest risk.

## Recommendation

Prioritized actions for security and engineering teams:

* Update the ModelScope library to the latest version, which removes the use of the unsafe `yaml.Loader` in favor of `yaml.SafeLoader` for configuration parsing.
* Audit all model repository sources currently in use to ensure they originate from trusted entities only.
* Implement strict sandboxing for any machine learning processes that ingest configuration data from unverified model repositories.
