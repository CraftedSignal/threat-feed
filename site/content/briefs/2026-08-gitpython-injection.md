---
title: Command Injection Vulnerability in GitPython
slug: 2026-08-gitpython-injection
description: GitPython versions prior to 3.1.51 are vulnerable to command injection because the library's security blocklist fails to account for Git command-line option abbreviation, allowing attackers to execute arbitrary commands.
date: "2026-08-01T13:52:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - command-injection
  - python
vendors:
  - gitpython-developers
products:
  - GitPython
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can bypass the unsafe options guard by using abbreviated option names like upload_p instead of upload_pack, which git resolves to dangerous options and executes arbitrary commands.
    confidence_band: high
cves:
  - id: CVE-2026-67325
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67325
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-2f96-g7mh-g2hx
  - https://www.vulncheck.com/advisories/gitpython-before-command-injection-via-option-prefix-abbreviation
---

GitPython, a widely used library for interacting with Git repositories in Python, contains a critical security vulnerability (CVE-2026-67325) in versions prior to 3.1.51. The library implements a blocklist to prevent the passing of dangerous command-line options to the underlying git binary. However, the blocklist is incomplete as it does not account for Git's feature that allows for the abbreviation of long command-line options.

An attacker can bypass these security restrictions by providing abbreviated versions of forbidden options, such as 'upload_p' instead of the full 'upload_pack'. When GitPython processes these inputs, the underlying system executes the git command with the injected, restricted flags. This leads to OS command injection, enabling unauthenticated or low-privilege users to achieve arbitrary command execution on the host running the application. This vulnerability is highly significant for any automated system or web application using GitPython to handle user-supplied Git repository configurations or operations.

## Impact

Successful exploitation allows remote attackers to execute arbitrary system commands with the privileges of the application process. This can lead to full system compromise, data exfiltration, or lateral movement within the environment. Applications leveraging GitPython for CI/CD pipelines, automated repository management, or source code analysis tools are at high risk.

## Recommendation

- Upgrade the GitPython library to version 3.1.51 or later immediately to incorporate the corrected blocklist logic.
- Review all application code utilizing GitPython to identify instances where user-supplied input is used to construct Git commands.
- Audit logs for suspicious git process arguments that utilize abbreviated long-options, such as --upload-p, --receive-p, or similar abbreviated variants that could indicate exploitation attempts.
- Apply the principle of least privilege by running applications that use GitPython under restricted service accounts to minimize the potential impact of a successful command injection.
