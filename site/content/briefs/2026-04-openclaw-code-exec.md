---
title: OpenClaw Arbitrary Code Execution via Malicious .npmrc File
slug: 2026-04-openclaw-code-exec
description: OpenClaw before 2026.3.24 is vulnerable to arbitrary code execution via local plugin and hook installation, where an attacker can craft a .npmrc file with a git executable override to execute malicious code during npm install.
date: "2026-04-10T17:17:04Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-35641
  - code-execution
  - npm
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35641
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35641
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-m3mh-3mpg-37hw
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-code-execution-via-npmrc-in-local-plugin-hook-installation
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect npm spawning git from unusual locations via npmrc
    description: Detects npm executing 'git' (or a renamed copy) from unexpected paths, which may indicate exploitation of CVE-2026-35641 via a malicious .npmrc file.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detect .npmrc Modification
    description: Detects modification to .npmrc files, which could indicate an attempt to inject malicious configurations.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

OpenClaw versions before 2026.3.24 are susceptible to arbitrary code execution. The vulnerability lies in the local plugin and hook installation process. An attacker can exploit this by crafting a malicious `.npmrc` file that overrides the `git` executable. During the `npm install` execution within the staged package directory, the system inadvertently triggers the attacker's specified programs. This happens because `npm` leverages `git` dependencies, and the overridden `git` path points to a malicious executable. This can allow complete system compromise, depending on the permissions of the user running the `npm install` command. This vulnerability was reported on April 10, 2026.

## Attack Chain

1.  Attacker identifies a target system running a vulnerable version of OpenClaw (prior to 2026.3.24).
2.  Attacker crafts a malicious `.npmrc` file. This file contains a configuration that overrides the `git` executable path to point to a malicious binary under attacker control. For example, `git=path/to/malicious/executable`.
3.  The attacker places the crafted `.npmrc` file in a location where the `npm` command will recognize it (e.g., the project directory, user's home directory, or a global configuration directory).
4.  The attacker triggers an `npm install` command execution within a project that processes plugins or hooks.
5.  During the `npm install` process, `npm` attempts to resolve git dependencies.
6.  Due to the `.npmrc` configuration, `npm` executes the attacker-controlled "git" executable specified in the .npmrc file instead of the legitimate git binary.
7.  The attacker-controlled executable executes arbitrary code on the system.
8.  The attacker achieves arbitrary code execution, potentially leading to system compromise, data exfiltration, or other malicious activities.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code with the privileges of the user running the `npm install` command. This can lead to complete system compromise, sensitive data leakage, or denial-of-service. While the specific number of victims is unknown, any system running a vulnerable version of OpenClaw is at risk. Sectors most likely to be impacted are those relying on OpenClaw for plugin and hook management.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.24 or later to patch the vulnerability (CVE-2026-35641).
*   Implement file integrity monitoring on `.npmrc` files to detect unauthorized modifications (file_event log source).
*   Monitor process executions where `npm` spawns child processes from unusual or unexpected paths, especially those outside standard installation directories (process_creation log source). Use the Sigma rule provided below to detect this behavior.
