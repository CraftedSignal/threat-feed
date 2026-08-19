---
title: GitPython Configuration-Name Injection Vulnerability
slug: 2026-08-gitpython-config-injection
description: GitPython versions prior to 3.1.58 are vulnerable to configuration-name injection, allowing attackers to forge arbitrary git-config directives and execute commands via core.sshCommand or core.hooksPath.
date: "2026-08-19T14:35:00Z"
lastmod: "2026-08-19T14:35:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - path-traversal
  - gitpython
  - cve-2026-76222
products:
  - GitPython
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: 'Attackers can inject malicious option names like ''sshCommand = touch /tmp/RCE #'' to execute arbitrary commands via core.sshCommand or core.hooksPath on the next git operation.'
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Attackers can craft malicious repositories with traversal sequences in submodule names that GitPython processes during submodule initialization.
    confidence_band: high
cves:
  - id: CVE-2026-76221
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76221
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-jm78-9fvv-mhgr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76222
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-hmq2-w58f-27jc
  - https://www.vulncheck.com/advisories/gitpython-before-path-traversal-via-gitmodules-submodule-name
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Patch GitPython to version 3.1.58 or later in all software projects.
      owner: Development
      due: 24h
      evidence: CVE-2026-76221 requires version 3.1.58 for remediation.
updates:
  - at: "2026-08-19T14:35:09Z"
    level: L2
    summary: added coverage for GitPython
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76222
---

GitPython, a widely used Python library for interacting with Git repositories, contains a configuration-name injection vulnerability in its option-name validator (CVE-2026-76221). The vulnerability exists in all versions prior to 3.1.58. It stems from improper neutralization of special characters - specifically equals signs, hash symbols, and whitespace - within the option-name validation logic.

An attacker capable of influencing the arguments passed to GitPython's configuration management functions can inject arbitrary git-config directives. By crafting malicious option names such as 'sshCommand = [command] #', an attacker can manipulate sensitive Git configuration keys like 'core.sshCommand' or 'core.hooksPath'. When the affected system performs a subsequent Git operation, the injected configuration is honored, leading to remote code execution (RCE) in the context of the user running the GitPython-powered application. This vulnerability is significant for CI/CD pipelines, web-based repository viewers, and automated build tools that leverage GitPython to process untrusted repository metadata.

## Impact

Successful exploitation allows for arbitrary command execution on systems running applications that use affected versions of GitPython. Given GitPython's prevalence in developer tooling, CI/CD runners, and automated security scanning platforms, the impact includes unauthorized code execution, potential pipeline compromise, and lateral movement within the development environment.

## Recommendation

* Upgrade GitPython to version 3.1.58 or later immediately across all environments.
* Audit applications using GitPython to ensure they do not pass unsanitized user-controlled input into Git configuration methods or option-name validators.
* Monitor for suspicious git-related configuration changes, such as unexpected setting of 'core.sshCommand' or 'core.hooksPath' via process command-line auditing.
