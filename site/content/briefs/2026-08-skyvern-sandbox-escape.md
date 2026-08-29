---
title: Skyvern TextPromptBlock Sandbox Escape
slug: 2026-08-skyvern-sandbox-escape
description: A sandbox escape vulnerability in Skyvern prior to version 1.0.45 allows unauthenticated attackers to achieve remote code execution by injecting malicious Jinja2 templates into prompt inputs.
date: "2026-08-29T13:38:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:skyvern:skyvern:*:*:*:*:*:*:*:*
tags:
  - cve-2026-82447
  - sandbox-escape
  - rce
  - vulnerability
vendors:
  - Skyvern
products:
  - Skyvern (< 1.0.45)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject malicious Jinja template syntax through workflow parameters or upstream block output to execute arbitrary code with server process privileges.
    confidence_band: high
cves:
  - id: CVE-2026-82447
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82447
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Skyvern to 1.0.45 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82447 mitigation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Skyvern to 1.0.45 or later.
      owner: IT Operations
      addresses: CVE-2026-82447
      evidence: Source provided fixed version
---

Skyvern versions prior to 1.0.45 are susceptible to a critical sandbox escape vulnerability located within the TextPromptBlock component. This flaw originates from an insecure rendering process where prompts are processed twice: once within a secured, sandboxed Jinja environment and subsequently within an unsandboxed environment. This architectural oversight allows an attacker to supply malicious Jinja2 template syntax through workflow parameters or upstream block outputs. When the application processes these inputs, the second, unsandboxed rendering pass executes the injected code with the full privileges of the underlying server process. This vulnerability is significant as it provides a direct path to remote code execution (RCE) without requiring existing credentials, potentially granting an adversary persistent access to the server's filesystem and environment variables.

## Impact

The vulnerability poses a severe risk to any organization deploying Skyvern for automated browser-based workflows. Successful exploitation enables unauthorized remote code execution, which can lead to complete server compromise, data exfiltration, or the deployment of additional malicious payloads. Organizations should prioritize patching to version 1.0.45 or higher immediately.

## Recommendation

* Upgrade all Skyvern instances to version 1.0.45 or later to eliminate the double-rendering vulnerability in the TextPromptBlock component.
* Review existing automated workflows for inputs that interact with the TextPromptBlock; restrict access to these parameters where possible.
* Isolate the Skyvern server from internal sensitive networks and ensure the process runs with the least privilege necessary to mitigate the impact of a potential sandbox escape.
