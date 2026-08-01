---
title: GitPython Improper Input Validation Leads to Command Injection
slug: 2026-08-gitpython-bypass
description: GitPython version 3.1.50 contains an input validation vulnerability that allows attackers to bypass security gates by using joined short-option forms, potentially leading to arbitrary command execution during repository cloning.
date: "2026-08-01T13:50:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-67324
  - command-injection
  - gitpython
  - python
vendors:
  - gitpython-developers
products:
  - GitPython (< 3.1.51)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can supply -u<helper> to bypass the gate that blocks --upload-pack/-u, causing Git to execute the specified helper command during clone.
    confidence_band: high
cves:
  - id: CVE-2026-67324
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67324
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-v396-v7q4-x2qj
  - https://www.vulncheck.com/advisories/gitpython-authentication-bypass-via-joined-short-options
---

GitPython versions prior to 3.1.51 contain an improper input validation vulnerability (CVE-2026-67324) that affects applications using the `Repo.clone_from` method. The library implements an 'unsafe-option' gate designed to prevent the injection of dangerous Git command-line options when `allow_unsafe_options` is set to `False`. However, the parser fails to correctly identify and block joined short-option forms, such as `-u<value>`, which represent the `--upload-pack` flag.

An attacker capable of influencing the arguments passed to `Repo.clone_from` can provide a malicious value for the `-u` flag, such as `-u<malicious_helper_command>`. Because the library's security gate does not properly sanitize this joined format, the underlying Git process executes the attacker-supplied command. This vulnerability poses a significant risk to CI/CD pipelines, automated build systems, and any application that uses GitPython to clone untrusted repositories. The issue is resolved in version 3.1.51.

## Impact

Successful exploitation allows an attacker to achieve arbitrary OS command execution with the privileges of the application running the GitPython library. This can lead to full system compromise, exfiltration of credentials or source code, and persistence within the affected environment. The vulnerability impacts any infrastructure utilizing GitPython 3.1.50 for automated repository management.

## Recommendation

1. Upgrade the GitPython library to version 3.1.51 or later immediately across all environments.
2. Audit codebases for any use of `Repo.clone_from` where input from external sources or untrusted users is used to construct the `multi_options` argument.
3. Implement strict input validation or allowlisting for repository clone options if upgrading is not immediately feasible.
4. Review system logs for unexpected child processes spawned by services executing Git operations, focusing on processes originating from the Python interpreter environment.
