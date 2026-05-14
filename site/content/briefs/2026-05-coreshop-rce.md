---
title: CoreShop Remote Code Execution via Malicious Pull Request
slug: 2026-05-coreshop-rce
description: CoreShop is vulnerable to remote code execution (RCE) via insecure `pull_request_target` configuration, allowing attackers to execute arbitrary code on the GitHub Actions runner by submitting a malicious pull request and potentially exfiltrate secrets or modify repository contents; tracked as CVE-2026-41249.
date: "2026-05-14T13:22:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github-actions
  - rce
  - pull-request
vendors:
  - Composer
products:
  - composer/coreshop/core-shop (= 5.0.0)
  - github.com
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-q58j-g3f4-h26h
rules:
  - title: Detect GitHub Actions Workflow Command Injection via bin/console
    description: Detects potential command injection attempts in GitHub Actions workflows by monitoring the execution of `bin/console` with suspicious command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Github Actions workflow modification
    description: Detects modification to Github Actions workflow files
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CoreShop is vulnerable to a remote code execution (RCE) vulnerability (CVE-2026-41249) due to an insecure configuration of the `pull_request_target` trigger in its GitHub Actions workflow (`.github/workflows/static.yml`). The workflow dangerously checks out unverified code from the pull request head (`ref: ${{ github.event.pull_request.head.ref }}`) and executes a script (`bin/console`) from this untrusted checkout. This allows any external attacker to achieve Remote Code Execution (RCE) on the GitHub Actions runner simply by submitting a malicious Pull Request, also known as a "Pwn Request" vulnerability. The vulnerable version is confirmed to be 5.0.0 of the CoreShop component.

## Attack Chain

1. An attacker forks the target CoreShop repository.
2. The attacker modifies a file within the forked repository that satisfies the `paths` condition defined in the `static.yml` workflow, such as `src/dummy.php` or `composer.json`.
3. The attacker crafts a malicious payload and injects it into the `bin/console` file within their forked repository. This payload is designed to execute arbitrary commands on the GitHub Actions runner.
4. The attacker commits the changes, including the modified `bin/console` file, to their forked repository.
5. The attacker opens a pull request (PR) targeting the `5.0` or `next` branch of the original CoreShop repository.
6. The `Static Tests` workflow is automatically triggered upon receiving the pull request.
7. The workflow executes the `bin/console` script from the attacker's branch, resulting in the execution of the malicious payload within the GitHub Actions runner environment.
8. The attacker obtains RCE within the runner's context, gaining access to secrets and potentially modifying repository contents.

## Impact

Successful exploitation allows an attacker to execute arbitrary code within the GitHub Actions runner environment. Because `pull_request_target` runs in the context of the base repository, the runner has access to repository secrets (e.g., `PIMCORE_SECRET`, `PIMCORE_PRODUCT_KEY`) loaded in the environment. An attacker can exfiltrate these secrets, modify repository contents (if the token has write permissions), or abuse the runner's computing resources. This can lead to sensitive data exposure, code tampering, and resource hijacking.

## Recommendation

*   Modify the GitHub Actions workflow (`.github/workflows/static.yml`) to avoid checking out untrusted PR code (`head.ref`) when using `pull_request_target`.
*   Implement a separated architecture using the `workflow_run` event, as suggested in the overview.
*   Monitor GitHub Actions logs for suspicious execution of `bin/console` with unexpected commands, using the detection rules provided below.
*   Apply the recommended mitigation from the advisory (https://github.com/advisories/GHSA-q58j-g3f4-h26h).
