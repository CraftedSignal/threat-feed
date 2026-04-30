---
title: OpenClaw Environment Variable Injection Vulnerability (CVE-2026-41384)
slug: 2026-04-openclaw-env-injection
description: OpenClaw before 2026.3.24 is vulnerable to environment variable injection, allowing attackers to inject malicious environment variables through crafted workspace configurations in the CLI backend, leading to potential code execution or sensitive data exposure.
date: "2026-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - environment-variable-injection
  - code-execution
  - cve-2026-41384
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Injection
cves:
  - id: CVE-2026-41384
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41384
  - https://github.com/openclaw/openclaw/commit/c2fb7f1948c3226732a630256b5179a60664ec24
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-vfw7-6rhc-6xxg
  - https://www.vulncheck.com/advisories/openclaw-environment-variable-injection-via-workspace-config-in-cli-backend
rules:
  - title: OpenClaw Suspicious Child Processes
    description: Detects suspicious child processes spawned by OpenClaw, which could indicate successful exploitation of CVE-2026-41384.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1053
      - T1059.001
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: OpenClaw Workspace Configuration Modification
    description: Detects modifications to OpenClaw workspace configuration files.
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

OpenClaw, a CLI tool, is vulnerable to environment variable injection (CVE-2026-41384) in versions prior to 2026.3.24. The vulnerability resides in the CLI backend runner and allows attackers to inject malicious environment variables into the backend process. This is achieved by crafting malicious workspace configurations. Successful exploitation can lead to arbitrary code execution within the context of the OpenClaw process or exposure of sensitive information handled by the application. This vulnerability poses a significant risk to systems using affected versions of OpenClaw, potentially allowing attackers to compromise the confidentiality, integrity, and availability of the system.

## Attack Chain

1.  Attacker crafts a malicious OpenClaw workspace configuration file. This file contains specially crafted environment variables designed to inject malicious code.
2.  The attacker gains access to a system where OpenClaw is installed, either through local access or by compromising an account that has access to modify OpenClaw workspace configurations.
3.  The attacker modifies the existing OpenClaw workspace configuration or creates a new one with the malicious environment variables.
4.  The user or system executes a command using the OpenClaw CLI, triggering the backend runner.
5.  The OpenClaw CLI backend runner parses the workspace configuration file, including the attacker-controlled environment variables.
6.  The backend runner spawns a new process, inheriting the injected environment variables.
7.  The injected environment variables cause the spawned process to execute arbitrary code, potentially downloading and executing malware or modifying system settings.
8.  The attacker achieves code execution, enabling them to perform various malicious activities such as data exfiltration, privilege escalation, or denial of service.

## Impact

Successful exploitation of this vulnerability (CVE-2026-41384) allows attackers to inject arbitrary environment variables, potentially leading to code execution or sensitive data exposure. Given the nature of CLI tools often used in automated scripting and deployment pipelines, this could lead to widespread compromise across multiple systems. The severity is rated as HIGH with a CVSS v3.1 score of 7.8.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.24 or later to remediate CVE-2026-41384.
*   Implement strict access control policies to limit who can modify OpenClaw workspace configurations to prevent unauthorized injection of malicious environment variables.
*   Monitor process creation events for unusual processes spawned by OpenClaw, using the `OpenClaw Suspicious Child Processes` Sigma rule.
*   Implement file integrity monitoring on OpenClaw workspace configuration files to detect unauthorized modifications.
