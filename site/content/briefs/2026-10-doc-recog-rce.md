---
title: OS Command Injection in doc-recog Library
slug: 2026-10-doc-recog-rce
description: The doc-recog library through version 1.1.6 is vulnerable to OS command injection via crafted document paths passed to the recog() or tag() functions.
date: "2026-10-14T16:33:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:*:doc-recog:*:*:*:*:*:*:*:*
products:
  - doc-recog (<= 1.1.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The doc-recog library contains an OS command injection vulnerability that allows attackers to execute commands by supplying crafted document paths.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The DocData._readPDF passes to a shell-based pdftotext exec call, running commands with Node.js process privileges.
    confidence_band: high
cves:
  - id: CVE-2026-110638
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110638
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade doc-recog to a version above 1.1.6
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-110638 patch availability
  mitigation_plan:
    - priority: immediate
      action: Implement strict input validation for document paths in application code
      owner: Development
      addresses: CVE-2026-110638
      evidence: Root cause analysis indicates lack of input sanitization
---

The doc-recog library (versions 1.1.6 and earlier) contains an OS command injection vulnerability, identified as CVE-2026-110638. The vulnerability originates in the DocData._readPDF method, which fails to sanitize user-provided document paths before passing them to a shell-based invocation of the pdftotext utility. By supplying a specially crafted document path containing shell metacharacters, such as command substitution sequences ($(cmd)) or backticks, an attacker can cause the underlying Node.js application to execute arbitrary commands with the privileges of the Node.js process. This vulnerability is highly critical due to the ease of exploitation and the potential for full system access depending on the context in which the Node.js application is running.

## Attack Chain

1. The application exposes an endpoint or interface that accepts document paths from a user.
2. The attacker provides a crafted document path input string containing malicious shell metacharacters like $(whoami) or `id`.
3. The application passes the malicious string to the recog() or tag() functions within the doc-recog library.
4. The library internally invokes the DocData._readPDF method.
5. The DocData._readPDF method fails to sanitize the input path and includes it directly in a shell command string formatted for the pdftotext binary.
6. The shell executes the command string, causing the injected malicious commands to trigger immediately.
7. The application returns the output of the injected command or proceeds to crash, while the attacker achieves unauthorized command execution on the host system.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary system commands on the server hosting the doc-recog library. This can lead to full system compromise, data exfiltration, or lateral movement within the environment. Given the widespread use of Node.js libraries in web applications, the scope of impact includes any service utilizing doc-recog for document processing.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Upgrade the doc-recog library to a patched version beyond 1.1.6 as soon as it becomes available.
- Audit all applications utilizing doc-recog to identify code paths where user input influences the document path parameter.
- Implement strict input validation on all file paths to ensure they conform to expected formats and contain only alphanumeric characters, preventing shell metacharacter injection.
- If upgrading is not immediately possible, implement a WAF rule to block requests containing shell substitution characters in paths directed toward the application.
