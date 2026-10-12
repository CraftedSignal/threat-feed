---
title: OS Command Injection in easy-pdf-merge
slug: 2026-10-easy-pdf-merge-command-injection
description: The easy-pdf-merge package (versions 0.1.0 through 0.2.6) contains an OS command injection vulnerability via unsanitized input to child_process.exec(), allowing arbitrary code execution.
date: "2026-10-12T22:39:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:easy-pdf-merge_project:easy-pdf-merge:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - nodejs
  - software-vulnerability
products:
  - easy-pdf-merge (0.1.0-0.2.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can supply file names or options containing double quotes, semicolons, $() or backticks, which child_process.exec() runs through a shell with the Node.js process privileges.
    confidence_band: high
cves:
  - id: CVE-2020-37279
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37279
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade easy-pdf-merge to version 0.2.7 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2020-37279 vulnerability report.
  mitigation_plan:
    - priority: immediate
      action: Remove or patch the vulnerable easy-pdf-merge dependency in all production applications.
      owner: IT Operations
      addresses: CVE-2020-37279
      evidence: Source advisory
---

The npm package 'easy-pdf-merge' (versions 0.1.0 through 0.2.6) is vulnerable to OS command injection due to improper handling of user-supplied input. An attacker can exploit this by injecting shell metacharacters such as double quotes, semicolons, dollar-parenthesis sequences $(), or backticks into the 'source' paths, 'destination' path, or 'maxHeap' option. These inputs are passed directly to the 'child_process.exec()' function in Node.js, which interprets them as shell commands. As a result, the injected commands are executed with the privileges of the Node.js application process. This vulnerability (CVE-2020-37279) presents a significant risk to any environment hosting applications that process user-defined PDF merge requests, as it allows for full remote code execution on the underlying host.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary system commands on the server running the vulnerable application. This may lead to total system compromise, exfiltration of sensitive data, or the establishment of persistent backdoors within the environment. Affected sectors include any organization utilizing Node.js applications that leverage the easy-pdf-merge library for document processing tasks.

## Recommendation

* Immediately update the 'easy-pdf-merge' package to a version beyond 0.2.6.
* If updating is not feasible, implement strict input validation and sanitization for all parameters passed to the library, ensuring the removal of shell metacharacters before processing.
* Audit applications utilizing this package for unauthorized child process execution using endpoint telemetry.
