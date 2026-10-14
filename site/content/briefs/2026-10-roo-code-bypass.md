---
title: Command Approval Bypass in Roo Code via Redirection
slug: 2026-10-roo-code-bypass
description: Roo Code through 3.54.0 contains a command approval bypass in getCommandDecision() allowing attackers to execute denied shell commands by prefixing them with a redirection operator.
date: "2026-10-14T04:36:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:roo_code:roo_code:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - command-execution
  - cve-2026-110202
vendors:
  - Roo Code
products:
  - Roo Code (<= 3.54.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The getCommandDecision() function allows attackers to auto-approve denied shell commands by prefixing them with a bare >& redirect.
    confidence_band: high
cves:
  - id: CVE-2026-110202
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110202
action_plan:
  priority: elevated
  owners:
    - SOC
    - Engineering
  immediate_actions:
    - action: Upgrade Roo Code to version 3.54.1 or later on all developer endpoints
      owner: Engineering
      due: 24h
      evidence: CVE-2026-110202 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade Roo Code to version 3.54.1
      owner: Engineering
      addresses: CVE-2026-110202
      evidence: NVD vulnerability disclosure
---

Roo Code versions 3.54.0 and earlier contain a command approval bypass vulnerability in the getCommandDecision() function. This vulnerability allows an attacker to execute denied shell commands on a developer's machine by utilizing a redirection operator (>&) as a prefix. The flaw stems from an insufficient validation mechanism in the allowlist logic, where an attacker can craft a payload via indirect prompt injection. By prefixing a malicious command with a redirection operator, the application incorrectly matches the input against an allowlist for a benign command (such as 'echo'), while the underlying shell proceeds to execute the intended malicious instructions. This poses a significant risk to developers using the extension in environments with sensitive access.
