---
title: 'Composer: Arbitrary File Write via Malicious Transitive Package Name'
slug: 2026-07-composer-arbitrary-file-write
description: A critical vulnerability, CVE-2026-59948, in Composer allows for arbitrary file write outside the project's vendor directory when processing a maliciously crafted package from an untrusted third-party repository during `install` or `update` operations, enabling code execution.
date: "2026-07-20T19:17:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - composer
  - php
  - supply-chain
  - arbitrary-file-write
  - code-execution
  - vulnerability
vendors:
  - Composer
products:
  - Composer (< 2.2.29)
  - Composer (>= 2.3.0, < 2.10.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: '...can be used to execute code outside the Composer project''s context...'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: '...by writing shell startup files, SSH `authorized_keys`, or a cron entry.'
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: 'It is a supply-chain issue: it requires a malicious or compromised package to be present in the dependency graph...'
    confidence_band: high
cves:
  - id: CVE-2026-59948
    cvss: 7
    epss: 0.00132
references:
  - https://github.com/advisories/GHSA-499r-g7pc-vmp9
---

A high-severity supply-chain vulnerability (CVE-2026-59948) has been identified in Composer, the popular PHP dependency manager. This flaw allows a malicious actor to achieve arbitrary file writes outside a project's intended `vendor/` directory and even outside the project root. This occurs when Composer attempts to install or update a dependency from an untrusted third-party repository, and that dependency has been maliciously crafted with an invalid package name that Composer fails to validate correctly. The vulnerability affects Composer versions older than 2.2.29 and versions between 2.3.0 and 2.10.2, as well as all 1.x versions. Attackers can exploit this to write arbitrary files such as shell startup files, SSH `authorized_keys`, or cron entries, leading to code execution outside the expected project context. This vulnerability is not remotely exploitable against a machine directly but requires the presence of a malicious or compromised package within the dependency graph.

## Attack Chain

1. An attacker crafts a malicious PHP package with an invalid `vendor/package` name format.
2. The attacker publishes this malicious package to an untrusted third-party Composer repository (not Packagist.org or Private Packagist).
3. A victim's Composer project is configured to use this untrusted repository for dependency resolution.
4. The victim executes `composer install` or `composer update` within their project, causing Composer to resolve and attempt to install dependencies, including the malicious package.
5. Composer processes the malicious package, and due to a lack of proper validation, constructs a file path outside the `vendor/` directory using the invalid package name.
6. Composer writes attacker-controlled content (e.g., shell startup script, SSH authorized_keys entry, cron job definition) to the arbitrary file path on the victim's system.
7. Upon the next relevant event (e.g., system boot, SSH connection, cron execution), the attacker's payload is executed, leading to remote code execution.

## Impact

Successful exploitation of CVE-2026-59948 results in arbitrary file write capabilities, which can lead to full system compromise through code execution. This supply-chain vulnerability allows attackers to inject malicious code into critical system locations such as shell startup files, SSH `authorized_keys`, or cron entries. This can grant attackers persistent access, elevate privileges, and ultimately allow them to take complete control of the compromised server. The scope of impact is broad, affecting any organization or individual using vulnerable Composer versions with untrusted third-party repositories.

## Recommendation

* Patch Composer immediately to version **2.2.29** or **2.10.2** to remediate CVE-2026-59948. Composer 1.x users should upgrade to a safe 2.x release.
* Configure Composer to avoid untrusted third-party package repositories. Review your `composer.json` and global Composer configurations for untrusted sources.
* If using untrusted repositories is unavoidable, mirror them through an internal repository solution, such as Private Packagist, which performs package name validation.
