---
title: Arbitrary Command Execution in Composer via Malicious Perforce Source URLs
slug: 2026-09-composer-rce
description: Composer versions before 2.10.3 and 2.2.30 are vulnerable to remote code execution when the Perforce CLI client is installed and a malicious package metadata source URL is processed (CVE-2026-84361).
date: "2026-09-08T21:50:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getcomposer:composer:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - rce
  - php
vendors:
  - Composer
products:
  - composer (>= 2.3.0, < 2.10.3)
  - composer (>= 1.0, < 2.2.30)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The p4 CLI client accepts addresses that mean run this local command instead of connect to this server.
    confidence_band: high
cves:
  - id: CVE-2026-84361
    epss: 0.00409
references:
  - https://github.com/advisories/GHSA-rvx4-ffvw-m9q3
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development Teams
  immediate_actions:
    - action: Upgrade Composer to version 2.10.3 or 2.2.30
      owner: Development Teams
      due: 24h
      evidence: Fixed in Composer 2.10.3 and 2.2.30.
    - action: Remove p4 CLI client from PATH on systems not requiring Perforce
      owner: IT Operations
      due: 48h
      evidence: Remove the p4 client from the PATH of machines that run Composer but do not use Perforce.
  mitigation_plan:
    - priority: immediate
      action: Remove p4 client from system PATH
      owner: IT Operations
      addresses: CVE-2026-84361
      evidence: This fully blocks this specific attack, since the vulnerability depends on that client being present.
---

Composer, a dependency manager for PHP, contains a vulnerability (CVE-2026-84361) that allows for arbitrary command execution when the Perforce (p4) CLI client is installed on the local system. The vulnerability exists because Composer fails to properly sanitize Perforce source URLs defined in package metadata before passing them to the `p4` command-line utility. Attackers who can control a package's `source` metadata - typically by utilizing private/third-party Composer repositories or untrusted `composer.lock` files - can provide specially crafted strings that the `p4` client interprets as local system commands rather than network connection endpoints.

This flaw impacts developers and CI environments where the `p4` client is present on the system `PATH`. When `composer install` or `composer update` is executed against a malicious repository or lock file, the commands injected via the Perforce source URL are executed with the privileges of the user running the Composer process. This vulnerability was addressed in Composer versions 2.10.3 and 2.2.30.

## Impact

Successful exploitation allows for full command execution on the target host, leading to system compromise, data theft, or lateral movement within build environments. The impact is highest in CI/CD pipelines where Composer processes untrusted dependencies, potentially compromising the entire development and deployment lifecycle. Organizations that do not use Perforce but have the `p4` CLI client installed on developer machines or build agents are also at risk.

## Recommendation

- Upgrade Composer to version 2.10.3 or 2.2.30 or later to ensure proper validation of Perforce source URLs.
- If upgrading is not immediately possible, remove the `p4` binary from the system `PATH` of all environments running Composer.
- Audit custom or third-party Composer repositories to ensure they are trusted and secure.
- Treat `composer.lock` files obtained from external, untrusted sources with extreme caution.
- Restrict the use of the `--prefer-source` flag in untrusted environments.
