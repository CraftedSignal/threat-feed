---
title: Remote Code Injection Vulnerability in marimo
slug: 2026-08-marimo-code-injection
description: Marimo versions before 0.23.15 contain a command injection vulnerability in the notebook configuration handler, allowing arbitrary command execution when a malicious notebook is opened in edit mode.
date: "2026-08-20T00:39:31Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - marimo
products:
  - marimo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: marimo launches the specified command as a local subprocess before any notebook cell is executed
    confidence_band: high
cves:
  - id: CVE-2026-75149
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75149
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch marimo installations to version 0.23.15 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-75149
---

Marimo versions prior to 0.23.15 contain a critical command injection vulnerability within the notebook configuration handler. The vulnerability stems from how the platform processes Model Context Protocol (MCP) server entries stored within a notebook file. An attacker can supply a specially crafted MCP server entry containing an arbitrary command string. When a target user opens a notebook containing this malicious configuration in edit mode, the marimo application automatically triggers the execution of the embedded command as a local subprocess. This occurs before any notebook cells are processed and requires no authentication or manual execution of cell code, significantly lowering the barrier for exploitation. This vulnerability affects all platforms where marimo is deployed and requires immediate patching to version 0.23.15 or later.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user running the marimo process. This can lead to full system compromise, data theft, or lateral movement within the victim's local environment. Because the exploit triggers upon opening the notebook, it poses a significant risk to developers and data scientists sharing notebook files.

## Recommendation

- Upgrade marimo to version 0.23.15 or higher immediately.
- Audit existing notebook files for suspicious MCP server configurations or unexpected command-line entries.
- Restrict the opening of untrusted .marimo notebook files until all environments are patched.
