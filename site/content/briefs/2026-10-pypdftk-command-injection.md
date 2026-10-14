---
title: OS Command Injection in pypdftk
slug: 2026-10-pypdftk-command-injection
description: The pypdftk library (<= 0.5) is vulnerable to OS command injection via insecure path handling in its core functions, allowing arbitrary command execution when using subprocess.Popen.
date: "2026-10-14T16:33:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:pypdftk_project:pypdftk:*:*:*:*:*:python:*:*
tags:
  - command-injection
  - python
  - supply-chain
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers controlling pdf_path or out_file can inject shell metacharacters interpreted by subprocess.Popen with shell=True to execute OS commands as the Python process.
    confidence_band: high
cves:
  - id: CVE-2026-110636
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110636
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Review codebase for usage of pypdftk and identify potential injection vectors
      owner: Application Security
      due: 48h
      evidence: CVE-2026-110636
  mitigation_plan:
    - priority: immediate
      action: Upgrade or remove pypdftk (<= 0.5)
      owner: IT Operations
      addresses: CVE-2026-110636
      evidence: nvd-advisory
---

The pypdftk library, in all versions up to and including 0.5, contains a critical OS command injection vulnerability. The flaw resides in the fill_form(), dump_data_fields(), and pdftk_cmd_util() functions, which improperly sanitize user-supplied file paths. When these functions are called, the library constructs shell commands containing the provided paths and passes them to Python's subprocess.Popen method with the shell=True argument enabled. This behavior allows an attacker who controls the input to the pdf_path or out_file parameters to inject arbitrary shell metacharacters. If successfully exploited, the attacker can execute system commands with the same privileges as the application process running the pypdftk library. This vulnerability poses a severe risk to any application that processes user-uploaded PDFs or dynamically generates PDF-related file paths using this library.

## Impact

Successful exploitation results in arbitrary code execution on the host machine running the affected Python application. The impact is critical, as it grants attackers the ability to compromise the underlying system, exfiltrate sensitive data, or move laterally within the network. The vulnerability affects any environment utilizing pypdftk <= 0.5 for PDF manipulation, regardless of the underlying operating system.

## Recommendation

* Immediately upgrade pypdftk to a version beyond 0.5 if a security update is available, or remove the library from the environment if no patch exists.
* Audit all applications using pypdftk to identify if user-controlled input reaches the pdf_path or out_file arguments in the identified vulnerable functions.
* Implement strict input validation and sanitization for all file paths before they are passed to any third-party PDF manipulation libraries.
* Transition to using subprocess.run or subprocess.Popen with shell=False, passing arguments as a list to prevent shell interpretation of metacharacters, even if the library itself remains vulnerable.
