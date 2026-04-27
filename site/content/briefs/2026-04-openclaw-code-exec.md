---
title: OpenClaw Arbitrary Code Execution via Malicious .npmrc File
slug: 2026-04-openclaw-code-exec
description: OpenClaw before 2026.3.24 is vulnerable to arbitrary code execution via local plugin and hook installation, where an attacker can craft a .npmrc file with a git executable override to execute malicious code during npm install.
date: "2026-04-10T17:17:04Z"
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

OpenClaw versions before 2026.3.24 are susceptible to arbitrary code execution. The vulnerability lies in the local plugin and hook installation process. An attacker can exploit this by crafting a malicious `.npmrc` file that overrides the `git` executable. During the `npm install` execution within the staged package directory, the system inadvertently triggers the attacker's specified programs. This happens because `npm` leverages `git` dependencies, and the overridden `git` path points to a…
