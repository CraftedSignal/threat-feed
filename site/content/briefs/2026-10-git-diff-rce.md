---
title: 'CVE-2026-110634: OS Command Injection in git-diff'
slug: 2026-10-git-diff-rce
description: The git-diff package before 2.0.7 is vulnerable to OS command injection via the gitDiff API, allowing arbitrary command execution with Node.js process privileges through crafted input strings.
date: "2026-10-14T16:32:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:git-diff_project:git-diff:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - rce
  - nodejs
products:
  - git-diff (< 2.0.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The git-diff package before 2.0.7 contains an OS command injection vulnerability that allows attackers to execute shell commands by supplying crafted strings to the gitDiff API.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: By supplying a crafted string containing command substitutions (such as $(cmd) or backticks) to the API, an attacker can trigger execution via shelljs.exec.
    confidence_band: high
cves:
  - id: CVE-2026-110634
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110634
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Upgrade git-diff dependency to version 2.0.7 or later
      owner: IT Operations
      due: 24h
      evidence: Source specifies 2.0.7 as the fixed version for CVE-2026-110634
  mitigation_plan:
    - priority: immediate
      action: Upgrade git-diff to version 2.0.7
      owner: IT Operations
      addresses: CVE-2026-110634
      evidence: NVD vulnerability details
---

The git-diff package version 2.0.6 and earlier contains a critical OS command injection vulnerability, identified as CVE-2026-110634. The flaw originates within the gitDiff API, which improperly sanitizes user-supplied input before passing it to the underlying system via the shelljs.exec function. An attacker with the ability to influence the document string processed by this API can inject shell metacharacters, specifically command substitutions using $() or backtick syntax. When the library processes these crafted strings, the Node.js application executes the injected commands with the full privileges of the host process. Given that many applications leverage git-diff for automated document processing, this vulnerability poses a significant risk of full system compromise or lateral movement if the hosting Node.js process has elevated system access. This vulnerability has a CVSS v3.1 base score of 9.8, reflecting the severity of unauthenticated remote command execution.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary commands on the server or workstation hosting the Node.js application. This could lead to data exfiltration, installation of persistent backdoors, or the deployment of ransomware. Any application utilizing git-diff versions prior to 2.0.7 as a dependency is currently susceptible to this attack vector.

## Recommendation

* Immediately upgrade the git-diff package to version 2.0.7 or later to implement the required input sanitization.
* Audit application code for instances where user-supplied content is passed directly to the gitDiff API without prior validation.
* Implement egress filtering at the network boundary to prevent spawned shells from reaching out to external command-and-control infrastructure.
