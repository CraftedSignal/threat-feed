---
title: Remote Code Execution in LaVague via Indirect Prompt Injection
slug: 2026-09-lavague-rce
description: LaVague version 0.2.35 contains a remote code execution vulnerability in the PythonFromMarkdownExtractor.extract_as_object function, allowing attackers to execute arbitrary code via indirect prompt injection.
date: "2026-09-04T15:32:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lavague:lavague:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - injection
  - ai-security
  - supply-chain
vendors:
  - LaVague
products:
  - LaVague (0.2.35)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Attackers can inject malicious Python code through web pages using indirect prompt injection to execute arbitrary code on the operator's host without review.
    confidence_band: high
cves:
  - id: CVE-2026-85694
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85694
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade or replace instances of LaVague 0.2.35
      owner: IT Operations
      due: 48h
      evidence: Source confirms vulnerable version is 0.2.35
  mitigation_plan:
    - priority: immediate
      action: Isolate systems running LaVague automation from untrusted web traffic
      owner: Security Operations
      addresses: CVE-2026-85694
      evidence: Indirect prompt injection vector requires access to untrusted web content
---

LaVague version 0.2.35 is vulnerable to remote code execution within its PythonFromMarkdownExtractor.extract_as_object function. This flaw exists due to the insecure evaluation of Python code that is extracted from language model (LLM) outputs. These outputs are derived from arbitrary web page content during automated browser interaction tasks. An attacker can craft a malicious web page containing instructions that trigger an indirect prompt injection attack. When a LaVague operator navigates to or processes this content, the LLM generates malicious Python code based on the injection, which is subsequently executed by the library on the operator's host system without validation or sandbox restrictions. This vulnerability poses a significant risk to users performing web automation or data extraction tasks.

## Impact

Successful exploitation allows for arbitrary code execution on the host system running the LaVague automation agent. This can lead to full system compromise, data theft, or further lateral movement within the network, depending on the privileges of the service account or user running the LaVague framework.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Identify all instances of LaVague (0.2.35) in the environment by scanning for package manifestations or process execution patterns.
- Review internal automation pipelines and restrict the ability of the LaVague framework to process content from untrusted, public-facing web sources.
- Monitor logs for unauthorized Python execution or subprocess calls originating from the directory or service account where LaVague is deployed.
