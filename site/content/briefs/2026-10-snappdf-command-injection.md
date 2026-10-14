---
title: OS Command Injection in Beganovich snappdf
slug: 2026-10-snappdf-command-injection
description: Beganovich snappdf versions 1.1.0 through 6.0.x are vulnerable to OS command injection via the setUrl() function on Windows, allowing unauthenticated attackers to achieve arbitrary code execution.
date: "2026-10-14T16:38:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:beganovich:snappdf:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - php
vendors:
  - Beganovich
products:
  - snappdf (1.1.0-6.0.x)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The setUrl() value... executesOnWindows() passes unescaped to PHP exec(), executing commands as the PHP process.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can supply cmd.exe metacharacters such as & in the setUrl() value.
    confidence_band: high
cves:
  - id: CVE-2026-110646
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110646
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade snappdf library to version 6.1.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110646 patch requirement.
  mitigation_plan:
    - priority: immediate
      action: Upgrade snappdf to 6.1.0 or later to remediate CVE-2026-110646.
      owner: IT Operations
      addresses: CVE-2026-110646
      evidence: Source documentation for version 6.1.0.
---

Beganovich snappdf, a library for generating PDFs from URLs in PHP applications, contains a critical OS command injection vulnerability (CVE-2026-110646) affecting versions 1.1.0 through 6.0.x. The vulnerability arises from insufficient sanitization of input passed to the setUrl() method on Windows environments. Specifically, the library's executeOnWindows() function passes the URL parameter unescaped to PHP's exec() system command. An attacker capable of influencing the input to setUrl() can inject shell metacharacters, such as the ampersand (&), to terminate the intended command and execute arbitrary system commands with the privileges of the underlying web server or PHP process. This flaw allows for full system compromise on affected Windows servers running vulnerable versions of the snappdf library.

## Impact

Successful exploitation allows for remote code execution (RCE) on Windows-based web servers hosting applications that utilize the vulnerable snappdf library. This can lead to total system compromise, data exfiltration, or deployment of secondary payloads within the target environment. The vulnerability affects any application utilizing snappdf for PDF generation that accepts user-controlled input for the URL parameter.

## Recommendation

- Upgrade the snappdf library to version 6.1.0 or later immediately to incorporate proper input sanitization.
- Audit existing PHP application code for any instance of the snappdf library calling setUrl() where the argument is derived from user input.
- Implement strict input validation and allowlisting for any URLs passed to PDF generation functions if upgrading immediately is not feasible.
