---
title: OpenClaw RCE via Build Tool Environment Variable Injection
slug: 2024-01-09-openclaw-rce
description: OpenClaw versions prior to 2026.4.8 are vulnerable to remote code execution (RCE) via build tool environment variable injection due to missing denylist entries for HGRCPATH, CARGO_BUILD_RUSTC_WRAPPER, RUSTC_WRAPPER, and MAKEFLAGS, allowing hostile environment variables to influence host exec commands.
date: "2026-04-09T14:22:29Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - rce
  - environment-variable-injection
  - openclaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569.002
    technique_name: 'System Services: Service Execution'
references:
  - https://github.com/advisories/GHSA-7437-7hg8-frrw
rules:
  - title: Detect Suspicious Process Creation from OpenClaw
    description: Detects suspicious processes spawned by OpenClaw, potentially indicating RCE.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Environment Variable Manipulation via OpenClaw
    description: Detects unusual environment variable usage in OpenClaw processes, potentially indicating environment variable injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw, a user-controlled local assistant, is vulnerable to a remote code execution (RCE) issue affecting versions prior to 2026.4.8. The vulnerability, identified as GHSA-cm8v-2vh9-cxf3, stems from missing denylist entries for environment variables that influence build tools. Specifically, HGRCPATH, CARGO_BUILD_RUSTC_WRAPPER, RUSTC_WRAPPER, and MAKEFLAGS were not properly sanitized, allowing a malicious actor to inject arbitrary commands into the build process. This can lead to the execution of untrusted code on the host system. The vulnerability was reported by @boy-hack of Tencent zhuque Lab. The fix is available in version 2026.4.8 and commit d7c3210cd6f5fdfdc1beff4c9541673e814354d5. This advisory is scoped to the OpenClaw trust model and does not assume a multi-tenant service boundary.

## Attack Chain

1.  The attacker identifies a vulnerable OpenClaw instance running a version prior to 2026.4.8.
2.  The attacker crafts malicious environment variables, such as HGRCPATH, CARGO_BUILD_RUSTC_WRAPPER, RUSTC_WRAPPER, or MAKEFLAGS, containing shell commands.
3.  The attacker triggers a build process within OpenClaw that utilizes the affected environment variables. This could involve providing a specific input or interacting with OpenClaw in a way that initiates a build operation.
4.  Due to the missing denylist, OpenClaw does not sanitize the malicious environment variables.
5.  The build tool, influenced by the attacker-controlled environment variables, executes the injected shell commands.
6.  The injected commands execute with the privileges of the OpenClaw process.
7.  The attacker gains arbitrary code execution on the host system.
8.  The attacker can now perform actions such as installing malware, exfiltrating data, or compromising other systems.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the system running OpenClaw. This could lead to complete system compromise, including data theft, malware installation, and further lateral movement within the network. Given OpenClaw's nature as a user-controlled local assistant, the impact is primarily on individual user systems. However, in environments where OpenClaw is deployed more broadly, the vulnerability could be leveraged to compromise multiple machines.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.8 or later to patch the vulnerability (see "Affected Packages / Versions").
*   Monitor process creation events for unexpected processes spawned by OpenClaw or its build tool subprocesses (see rules below).
*   Implement additional input validation and sanitization measures to prevent environment variable injection in other applications.
*   Review and harden build processes to limit the influence of environment variables.
