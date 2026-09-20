---
title: OS Command Injection in getID3 shell-out handlers
slug: 2026-09-getid3-injection
description: getID3 versions prior to 1.9.26 are vulnerable to OS command injection via unescaped shell metacharacters in filenames, allowing for arbitrary command execution.
date: "2026-09-20T14:21:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getid3:getid3:*:*:*:*:*:*:*:*
products:
  - getID3 (< 1.9.26)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft malicious filenames containing shell metacharacters to inject arbitrary commands executed with the privileges of the process embedding getID3.
    confidence_band: high
cves:
  - id: CVE-2026-94106
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94106
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade getID3 to 1.9.26 or later
      owner: Development
      due: 24h
      evidence: CVE-2026-94106 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade getID3 to version 1.9.26 or later
      owner: IT Operations
      addresses: CVE-2026-94106
      evidence: NVD vulnerability details for CVE-2026-94106
---

The PHP library getID3, widely used for extracting metadata from media files, contains a critical OS command injection vulnerability (CVE-2026-94106) in versions prior to 1.9.26. The vulnerability exists within the library's shell-out handlers, which are responsible for executing external system binaries to process specific file formats. The handlers fail to properly sanitize or escape filenames passed as arguments to these commands. 

An attacker who can influence the filenames processed by an application using an affected version of getID3 can inject arbitrary shell metacharacters (such as backticks, semicolons, or pipes). When the application calls the vulnerable handler, the injected commands are executed with the privileges of the web server or the process embedding the getID3 library. This flaw allows for remote code execution, potentially resulting in full system compromise depending on the execution context of the host application.

## Impact

The vulnerability poses a high risk to any web application or media processing pipeline that uses getID3 to handle user-supplied files. Successful exploitation leads to arbitrary code execution, which can be leveraged for data exfiltration, lateral movement within the network, or persistent system compromise. Given the prevalence of getID3 in various CMS plugins and media management tools, the potential attack surface is significant across multiple industry sectors.

## Recommendation

* Update the getID3 library to version 1.9.26 or later immediately.
* Audit applications utilizing getID3 to ensure filenames are validated and sanitized before being passed to library functions.
* Implement strict file upload policies that rename user-provided files to randomized, safe strings before processing.
* Restrict the permissions of the user account running the web application to the minimum necessary level to contain the potential impact of command injection.
