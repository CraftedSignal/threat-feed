---
title: Command Injection in PHP_CodeSniffer via Malicious Filenames
slug: 2026-08-php-codesniffer-command-injection
description: PHP_CodeSniffer versions prior to 3.13.6 and 4.0.2 are vulnerable to command injection via the Gitblame, Hgblame, and Svnblame reports when processing files containing shell metacharacters.
date: "2026-08-07T03:29:39Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - PHPCSStandards
products:
  - PHP_CodeSniffer (3.x)
  - PHP_CodeSniffer (4.x)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The code creating the Gitblame, Hgblame and Svnblame report(s) processes a file whose name contains shell metacharacters.
    confidence_band: high
cves:
  - id: CVE-2026-67434
references:
  - https://github.com/advisories/GHSA-hmqg-cxww-wqhq
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-67434
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevSecOps
  immediate_actions:
    - action: Upgrade PHP_CodeSniffer to v3.13.6/4.0.2 in all CI environments
      owner: DevSecOps
      due: 48h
      evidence: Vendor advisory recommends upgrade to patched versions
  mitigation_plan:
    - priority: immediate
      action: Disable Gitblame, Hgblame, and Svnblame reports in CI/CD pipelines scanning untrusted code
      owner: DevSecOps
      addresses: CVE-2026-67434
      evidence: Workaround documented in GHSA-hmqg-cxww-wqhq
---

PHP_CodeSniffer contains a critical command injection vulnerability, assigned CVE-2026-67434, affecting its `Gitblame`, `Hgblame`, and `Svnblame` reporting modules. The issue arises when the tool processes filenames containing shell metacharacters such as backticks, semicolons, or pipes. If these reports are executed against untrusted repositories - common in CI/CD pipelines, automated pull request review services, or local analysis of third-party source code - an attacker can gain arbitrary command execution on the host machine. The vulnerability is present in versions prior to 3.13.6 for the 3.x branch and prior to 4.0.2 for the 4.x branch. Systems running on platforms that permit shell metacharacters in file paths are at highest risk.

## Impact

Successful exploitation allows attackers to execute arbitrary system commands with the privileges of the user running the PHP_CodeSniffer process. This poses a significant risk to CI/CD infrastructure, where malicious pull requests or commits can trigger code execution upon analysis, potentially leading to credential exfiltration, persistence, or supply chain compromise.

## Recommendation

- Upgrade PHP_CodeSniffer to version 3.13.6 or 4.0.2 immediately.
- If upgrading is not immediately possible, restrict the use of `Gitblame`, `Hgblame`, or `Svnblame` reports when scanning untrusted source trees.
- Audit CI/CD pipeline configurations to identify jobs that utilize these specific reporting flags on untrusted input and switch to the `Full` report or other safe reporting formats.
