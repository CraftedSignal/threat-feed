---
title: WebdriverIO BrowserStack Service Command Injection Vulnerability (CVE-2026-25244)
slug: 2026-05-webdriverio-cmd-injection
description: A command injection vulnerability (CVE-2026-25244) in `@wdio/browserstack-service` allows remote code execution (RCE) by processing malicious git branch names in test orchestration, where an attacker can inject shell commands via a crafted git repository.
date: "2026-05-11T17:55:09Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - command-injection
  - rce
  - supply-chain
vendors:
  - BrowserStack
products:
  - '@wdio/browserstack-service (<= 9.23.2)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-5c46-x3qw-q7j7
  - https://github.com/webdriverio/webdriverio/blob/ea0e3e00288abced4c739ff9e46c46977b7cdbd2/packages/wdio-browserstack-service/src/testorchestration/helpers.ts#L204
rules:
  - title: Detect CVE-2026-25244 Exploitation — Suspicious Process Execution via wdio
    description: Detects CVE-2026-25244 exploitation — Monitors for process execution events originating from wdio processes with shell metacharacters in the command line, indicating potential command injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
      - supply_chain
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-25244 Exploitation — File Creation in /tmp via wdio Injection
    description: Detects CVE-2026-25244 exploitation — Monitors for file creation events in /tmp directory originating from a wdio process with shell command injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
      - supply_chain
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical command injection vulnerability, tracked as CVE-2026-25244, has been identified in the `@wdio/browserstack-service` npm package, specifically affecting versions 9.23.2 and earlier. The vulnerability stems from the improper handling of git branch names within the test orchestration functionality. An attacker can exploit this flaw by crafting a malicious git repository with a branch name containing shell command injection payloads. When WebdriverIO processes this repository, the unsanitized branch name is passed to `execSync()`, leading to arbitrary command execution on the system. This poses a significant risk to CI/CD environments and developer workstations, potentially leading to complete system compromise and supply chain attacks.

## Attack Chain

1. An attacker creates a malicious git repository, crafting a branch name embedded with shell command injection payloads (e.g., `main;touch${IFS}/tmp/pwned.txt;echo${IFS}PWNED`).
2. The attacker configures WebdriverIO to utilize the malicious repository, either explicitly through `testOrchestrationOptions.runSmartSelection.source` or implicitly by placing the repository in the current working directory.
3. WebdriverIO initiates test orchestration, triggering the `getGitMetadataForAISelection()` function within the `@wdio/browserstack-service`.
4. The `getGitMetadataForAISelection()` function retrieves the malicious branch name from the git repository.
5. The retrieved branch name, containing the injected shell commands, is directly interpolated into an `execSync()` call.
6. The `execSync()` function executes the crafted shell command, leading to arbitrary code execution on the host system.
7. The attacker achieves remote code execution, enabling them to perform actions such as creating files, modifying system configurations, or exfiltrating sensitive data.
8. The attacker can leverage the compromised system for lateral movement, further compromising the network or modifying build artifacts for a supply chain attack.

## Impact

Successful exploitation of CVE-2026-25244 can result in Remote Code Execution on CI/CD servers or developer machines. This allows attackers to perform Information Disclosure by accessing environment variables, secrets, and credentials. Further impact includes Data Exfiltration of source code, SSH keys, and configuration files, System Compromise through backdoor installation and lateral movement, and Supply Chain Attacks through modification of build artifacts. All versions of `@wdio/browserstack-service` up to and including 9.23.2 are vulnerable.

## Recommendation

*   Upgrade `@wdio/browserstack-service` to a version higher than 9.23.2 to remediate CVE-2026-25244.
*   Implement input validation and sanitization for git branch names to prevent command injection.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts in your environment.
*   Enable process creation logging with command-line arguments to facilitate detection and investigation of command injection attempts.
