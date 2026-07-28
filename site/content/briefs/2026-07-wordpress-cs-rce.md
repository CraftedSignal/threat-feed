---
title: WordPress Coding Standards Contains an Arbitrary Code Execution Vulnerability
slug: 2026-07-wordpress-cs-rce
description: WordPress Coding Standards (WordPressCS) versions before 3.4.1 are vulnerable to arbitrary code execution due to a flaw in the `WordPress.WP.EnqueuedResourceParameters` sniff, allowing an attacker to execute arbitrary commands on the scanning host by crafting a malicious `$ver` argument, posing a risk for users running PHPCS with specific rulesets in CI pipelines or developer environments.
date: "2026-07-28T14:32:34Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - wordpress
  - code-execution
  - vulnerability
  - php
  - ci/cd
vendors:
  - WordPress
products:
  - 'WordPress Coding Standards (vulnerable: >= 0.14.1, < 3.4.1)'
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a maliciously crafted `$ver` argument such as `'system'('id')` would be executed during the scan.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-3pwp-g2mj-5p3v
---

WordPress Coding Standards (WordPressCS) versions prior to 3.4.1 contain a critical arbitrary code execution vulnerability, identified as CVE-2026-45293, affecting the `WordPress.WP.EnqueuedResourceParameters` sniff. This vulnerability allows an attacker to execute arbitrary commands on the host running PHP CodeSniffer (PHPCS) if it processes untrusted PHP code. Specifically, a malicious `$ver` argument crafted within functions like `wp_enqueue_script()` or `wp_register_script()` can be directly executed via `eval()` by the vulnerable sniff during the code analysis process. This poses a significant risk to development environments, CI/CD pipelines, and any developer machines reviewing third-party code, particularly when using the `WordPress` or `WordPress-Extra` rulesets. The vulnerability does not require active exploitation of a WordPress site itself but targets the code scanning infrastructure.

## Attack Chain

1. An attacker crafts a malicious PHP code snippet, for instance, by embedding a system command within the `$ver` argument of `wp_enqueue_script()` or `wp_register_script()`, such as `wp_enqueue_script('handle', 'src', [], 'system'('id'))`.
2. The attacker introduces this malicious code into a project, potentially via a pull request in a software development lifecycle (SDLC) that uses automated code linting.
3. A developer or an automated CI/CD pipeline runs PHPCS with the affected WordPressCS versions (specifically, the `WordPress` or `WordPress-Extra` rulesets) to analyze the untrusted PHP code.
4. During the scan, the `WordPress.WP.EnqueuedResourceParameters` sniff is triggered to check the `$ver` argument for falsy values.
5. The sniff's internal `is_falsy()` method reconstructs the attacker's malicious `$ver` argument.
6. The reconstructed malicious argument is then passed to and executed by PHP's `eval()` function within the context of the scanning host.
7. The embedded system command, such as `system('id')`, is executed on the CI/CD server or developer's machine.
8. The attacker achieves arbitrary code execution on the host performing the code analysis, potentially leading to compromise of the development environment or infrastructure.

## Impact

This vulnerability directly leads to arbitrary code execution on systems running PHPCS with affected WordPressCS versions. While it does not directly compromise WordPress installations, it significantly impacts developer workstations, CI/CD pipelines, and any infrastructure responsible for code review and static analysis. A successful exploitation grants the attacker control over the scanning host, allowing for further lateral movement, data exfiltration, or supply chain attacks by injecting malicious code into repositories. All organizations utilizing WordPressCS for linting PHP code, particularly those processing untrusted code, are at risk.

## Recommendation

* Immediately upgrade WordPress Coding Standards to version 3.4.1 or later to remediate CVE-2026-45293.
* If immediate upgrade is not feasible, disable the `WordPress.WP.EnqueuedResourceParameters` sniff by adding an `<exclude>` tag to your custom ruleset, as detailed in the workaround section of the advisory.
