---
title: Remote Code Execution in Coze Studio via Workflow Nodes
slug: 2026-10-coze-studio-rce
description: Coze Studio versions prior to 0.5.0 allow authenticated users to execute arbitrary commands by bypassing sandbox protections in Python workflow nodes.
date: "2026-10-20T02:32:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:coze:coze_studio:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - sandbox-escape
  - python
vendors:
  - Coze
products:
  - Coze Studio (< 0.5.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: Attackers can bypass the regex import filter with __import__('subprocess') to run commands.
    confidence_band: high
cves:
  - id: CVE-2026-77934
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77934
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Coze Studio to 0.5.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-77934 resolution
  mitigation_plan:
    - priority: immediate
      action: Upgrade Coze Studio to version 0.5.0
      owner: IT Operations
      addresses: CVE-2026-77934
      evidence: NVD advisory
---

Coze Studio versions prior to 0.5.0 contain an insecure default configuration that fails to properly sandbox Python code execution within workflow nodes. An authenticated attacker can manipulate these workflow nodes to execute arbitrary code within a subprocess. By bypassing the existing regex-based import filters - specifically using the `__import__('subprocess')` technique - an attacker can gain command execution on the host environment. This vulnerability poses a significant risk to the integrity and confidentiality of the Coze Studio instance, as successful exploitation allows an attacker to exfiltrate sensitive environment variables, extract model API keys, and pivot to connected backend services such as MySQL, MinIO, Redis, and etcd.

## Impact

Successful exploitation of CVE-2026-77934 enables an attacker to achieve remote code execution as the user running the Coze Studio service. This access facilitates the theft of credentials (API keys) and unauthorized access to internal data stores (MySQL, MinIO, Redis, etcd), potentially resulting in full database compromise or cross-environment lateral movement.

## Recommendation

1. Upgrade Coze Studio to version 0.5.0 or later to ensure proper sandboxing of Python code execution.
2. Review logs for unexpected `subprocess` or `os.system` calls originating from the service process.
3. Restrict network access for the Coze Studio backend infrastructure to prevent unauthorized access to internal databases (MySQL, Redis, etcd, MinIO) if the process is compromised.
