---
title: Remote Code Execution in GitPython via Repo.init
slug: 2026-08-gitpython-rce
description: GitPython versions before 3.1.58 are vulnerable to RCE via improper validation of arguments in the Repo.init method, allowing attackers to inject malicious git hooks.
date: "2026-08-19T14:34:37Z"
lastmod: "2026-08-25T04:07:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - argument-injection
  - gitpython
  - cve-2026-76219
  - cve-2026-76220
  - rce
  - path-traversal
  - cve-2026-78677
vendors:
  - gitpython-developers
products:
  - GitPython
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can supply a template parameter pointing to a directory with malicious git hooks that execute arbitrary code when git operations are performed on the initialized repository.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An attacker can supply a malicious .gitmodules file containing an [include] directive that points to a sensitive local file.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Attackers can pass a separate_git_dir parameter to Repo.clone_from() or Repo.clone() to redirect repository metadata to an attacker-controlled filesystem path, enabling arbitrary directory creation and potential hook execution.
    confidence_band: high
cves:
  - id: CVE-2026-76218
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76218
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-9rj7-rf2p-w77r
  - https://www.vulncheck.com/advisories/gitpython-before-remote-code-execution-via-repo-init
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76219
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-4gmw-gg2m-w46p
  - https://www.vulncheck.com/advisories/gitpython-before-arbitrary-file-overwrite-via-read-tree
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76220
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-wvpp-8hx9-p66j
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78675
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-7833-fr7j-v32q
  - https://www.vulncheck.com/advisories/gitpython-before-local-file-content-disclosure-via-gitmodules
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78677
  - https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-8mcc-hrx5-hvxc
  - https://www.vulncheck.com/advisories/gitpython-before-path-traversal-via-separate-git-dir
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade GitPython dependency to 3.1.58 in all project requirements and environment configurations.
      owner: IT Operations
      due: 24h
      evidence: GitPython before 3.1.58 contains a remote code execution vulnerability
  mitigation_plan:
    - priority: immediate
      action: Identify and sanitize all calls to Repo.init that utilize the template parameter.
      owner: Security Engineering
      addresses: CVE-2026-76218
      evidence: Attackers can supply a template parameter pointing to a directory with malicious git hooks
updates:
  - at: "2026-08-19T14:34:46Z"
    level: L2
    summary: added coverage for GitPython
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76219
  - at: "2026-08-19T14:34:54Z"
    level: L2
    summary: added coverage for GitPython
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76220
  - at: "2026-08-25T04:06:57Z"
    level: L2
    summary: added coverage for GitPython
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-78675
  - at: "2026-08-25T04:07:06Z"
    level: L2
    summary: added coverage for GitPython
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-78677
---

GitPython versions before 3.1.58 contain a remote code execution (RCE) vulnerability within the `Repo.init` method. The flaw is categorized as an argument injection vulnerability (CWE-88), where the library fails to properly neutralize arguments passed to the underlying Git command. An attacker can provide a `template` parameter that points to a user-controlled directory containing malicious git hooks. When the application or user performs subsequent git operations on the initialized repository, the attacker-provided hooks are executed with the privileges of the process running the GitPython library. This vulnerability poses a high risk to applications that expose repository initialization functionality to untrusted inputs or users.

## Impact

Successful exploitation allows for arbitrary code execution on the host machine running the affected application. This vulnerability is applicable to any environment using GitPython for repository automation or management where user input influences the `Repo.init` parameters. Given that GitPython is widely integrated into CI/CD pipelines, automation scripts, and developer tools, the impact could range from complete system compromise to lateral movement within a development environment.

## Recommendation

- Upgrade the `GitPython` package to version 3.1.58 or later immediately to incorporate the necessary input validation for the `Repo.init` method.
- Audit existing implementations that utilize `Repo.init` to ensure that the `template` parameter is not sourced from untrusted or user-supplied input.
- Implement strict input validation or allowlisting for any parameters passed to `git` related operations if the application architecture prevents immediate library updates.
