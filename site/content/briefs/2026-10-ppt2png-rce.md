---
title: OS Command Injection in ppt2png Library
slug: 2026-10-ppt2png-rce
description: The ppt2png npm package (version 0.0.6 and earlier) is vulnerable to OS command injection via unsanitized file path arguments passed to child_process.exec(), enabling arbitrary code execution.
date: "2026-10-08T19:39:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ppt2png_project:ppt2png:*:*:*:*:*:node.js:*:*
tags:
  - supply-chain
  - command-injection
  - nodejs
  - cve-2026-107699
products:
  - ppt2png (<= 0.0.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can append shell metacharacters such as ';' to file names passed to child_process.exec() in ppt2png.js, running commands with Node.js process privileges.
    confidence_band: high
cves:
  - id: CVE-2026-107699
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107699
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: Audit codebase for usage of ppt2png package and transition to alternative libraries or implement strict input sanitization.
      owner: Development
      due: 48h
      evidence: CVE-2026-107699 advisory
  mitigation_plan:
    - priority: immediate
      action: Patch or remove dependency on ppt2png <= 0.0.6
      owner: Development
      addresses: CVE-2026-107699
      evidence: Source advisory
---

The ppt2png npm package version 0.0.6 and earlier contains a critical OS command injection vulnerability, identified as CVE-2026-107699. The vulnerability stems from improper sanitization of user-supplied input and output path arguments within the ppt2png.js module. Specifically, the library uses the Node.js `child_process.exec()` function to execute system commands, but it fails to escape or sanitize shell metacharacters provided in filename parameters. An attacker can exploit this by injecting characters like the semicolon (`;`) into an argument, allowing them to terminate the intended command and append malicious OS commands. These commands execute with the same privileges as the Node.js application process. This vulnerability presents a high risk to any application using the library to process user-provided file paths, potentially leading to full system compromise depending on the process context.

## Impact

Successful exploitation allows for arbitrary code execution on the server hosting the application. This could result in unauthorized data access, exfiltration of sensitive information, or the deployment of persistent malware within the infrastructure of organizations utilizing the vulnerable package in their software supply chain.

## Recommendation

* Identify all applications utilizing the ppt2png npm package version 0.0.6 or earlier and update to a remediated version if available.
* If no patched version exists, implement input validation to sanitize all filenames and file path arguments, rejecting any strings containing shell metacharacters such as `;`, `|`, `&`, `$`, or `>`.
* Run the Node.js application process with the least privilege possible to minimize the impact of potential command execution.
