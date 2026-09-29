---
title: PHPCSUtils Arbitrary Code Execution via AbstractArrayDeclarationSniff
slug: 2026-09-phpcsutils-rce
description: PHPCSUtils versions 1.0.0-alpha1 through 1.2.2 are vulnerable to remote code execution due to insecure use of eval() within the AbstractArrayDeclarationSniff::getActualArrayKey() method.
date: "2026-09-29T22:19:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:phpcsstandards:phpcsutils:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - static-analysis
  - supply-chain
vendors:
  - PHPCSStandards
products:
  - PHPCSUtils (>= 1.0.0-alpha1, < 1.2.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability happens when the method determines the value of an array key using eval(), allowing arbitrary command execution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-r6hr-vr92-vv28
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-65954
action_plan:
  priority: immediate_escalation
  owners:
    - Security Operations
    - DevOps
  immediate_actions:
    - action: Upgrade PHPCSUtils to version 1.2.3 or later
      owner: DevOps
      due: 24h
      evidence: This issue has been fixed in PHPCSUtils 1.2.3.
  mitigation_plan:
    - priority: immediate
      action: Disable vulnerable sniffs via XML ruleset configuration
      owner: DevOps
      addresses: CVE-2026-65954
      evidence: Users who cannot upgrade immediately can disable the sniffs that reach the vulnerable method.
---

PHPCSUtils, a utility library used by PHP_CodeSniffer for static analysis, contains a critical arbitrary code execution vulnerability identified as CVE-2026-65954. The issue resides in the `PHPCSUtils\AbstractSniffs\AbstractArrayDeclarationSniff::getActualArrayKey()` method, which performs improper input validation when processing array keys. Specifically, the method utilizes the `eval()` function to determine key values, allowing an attacker to inject arbitrary PHP code within a maliciously crafted array key.

This vulnerability impacts any linting or static analysis pipeline that utilizes PHP_CodeSniffer with rulesets extending the vulnerable `AbstractArrayDeclarationSniff` class. Notable examples of affected downstream sniffs include `Universal.Arrays.DuplicateArrayKey` and `Universal.Arrays.MixedArrayKeyTypes` from the PHPCSExtra package. Defenders should note that this vulnerability can be triggered automatically during CI/CD processes, pull request linting, or local developer analysis if the scanned target repository contains malicious PHP code. Successful exploitation results in the execution of arbitrary commands with the privileges of the user running the PHPCS process.

## Attack Chain

1. Attacker crafts a malicious PHP file containing an array with a specially formatted key, such as `'system'('id')`.
2. The target environment initiates a static analysis scan using `phpcs`.
3. The scanning engine loads a ruleset that includes a sniff extending `AbstractArrayDeclarationSniff`.
4. The scanner identifies the malicious array structure and triggers the `getActualArrayKey()` method.
5. The method passes the malicious array key string directly into an `eval()` call.
6. The PHP runtime executes the injected code within the context of the scanning host's user.
7. The attacker achieves arbitrary code execution on the build server, developer workstation, or CI/CD container.

## Impact

Successful exploitation allows for full command execution on the host machine running the static analysis. This poses a significant risk to CI/CD environments where pull requests from untrusted contributors are automatically scanned. If the scanning host is compromised, attackers may gain access to sensitive repository secrets, pipeline environment variables, or establish persistence within the development infrastructure.

## Recommendation

1. Upgrade PHPCSUtils to version 1.2.3 or later immediately to resolve CVE-2026-65954.
2. If an immediate upgrade is not feasible, identify and disable the affected sniffs (e.g., `Universal.Arrays.DuplicateArrayKey` and `Universal.Arrays.MixedArrayKeyTypes`) within your ruleset XML files using the `<exclude>` tag.
3. Verify the removal of affected sniffs by executing `phpcs -e --standard=/path/to/ruleset.xml` to ensure they no longer appear in the active sniff list.
4. Monitor CI/CD logs for processes spawning shells or making unexpected network connections initiated by the PHPCS linter.
