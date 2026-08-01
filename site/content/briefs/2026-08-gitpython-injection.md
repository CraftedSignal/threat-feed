---
title: GitPython Command Injection and File Truncation Vulnerability
slug: 2026-08-gitpython-injection
description: GitPython versions prior to 3.1.51 contain vulnerabilities allowing command injection and arbitrary file truncation through insufficient sanitization of keyword arguments and revision inputs.
date: "2026-08-01T13:52:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - python
  - library-vulnerability
vendors:
  - GitPython
products:
  - GitPython (< 3.1.51)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The flaw allows command injection via options such as --exec/--upload-pack leading to arbitrary command execution.
    confidence_band: high
cves:
  - id: CVE-2026-67323
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67323
---

GitPython versions before 3.1.51 are susceptible to command injection and arbitrary file manipulation due to improper input validation when handling keyword arguments and revision strings. Specifically, the methods Repo.archive() and git.ls_remote() fail to sanitize keyword arguments, enabling attackers to inject dangerous Git options such as --exec or --upload-pack, which results in arbitrary command execution on the host system. Furthermore, the methods Repo.iter_commits() and Repo.blame() do not validate revision arguments for leading dashes. This allows an attacker to pass crafted strings such as --output=&lt;path>, causing the underlying Git process to open and truncate arbitrary files on the filesystem. This vulnerability affects any application that passes untrusted user input directly into these specific GitPython method arguments.

## Impact

The vulnerability allows for remote command execution and local file destruction. An attacker who can influence the inputs processed by these GitPython methods can achieve full control over the application's runtime environment or perform denial-of-service attacks by corrupting critical system or application files. This impacts any environment running software that integrates GitPython versions older than 3.1.51 for repository management or CI/CD pipeline automation.

## Recommendation

- Upgrade the GitPython library to version 3.1.51 or later in all application dependencies to remediate CVE-2026-67323.
- Audit application code to identify where user-supplied input is passed as arguments to Repo.archive(), git.ls_remote(), Repo.iter_commits(), and Repo.blame().
- Implement strict input validation or allowlisting for any variables that are passed to GitPython methods to prevent the injection of flags starting with dashes.
- Review application logs for unusual process command lines triggered by Python application workers.
