---
title: OpenClaw MCP Stdio Server Environment Variable Injection Vulnerability (CVE-2026-44995)
slug: 2026-05-openclaw-env-var-injection
description: OpenClaw before 2026.4.20 contains an improper environment variable validation vulnerability (CVE-2026-44995) in MCP stdio server configuration, allowing attackers to execute arbitrary code via malicious workspace configurations that pass dangerous startup variables.
date: "2026-05-11T18:18:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - code-execution
  - environment-variable-injection
vendors:
  - OpenClaw
products:
  - OpenClaw
  - MCP stdio server
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1546
    technique_name: Event Triggered Execution
cves:
  - id: CVE-2026-44995
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44995
  - https://github.com/openclaw/openclaw/commit/62fa5071896e95edc7f67d1cebc70a2859e283af
  - https://github.com/openclaw/openclaw/commit/85d86ebc4bf3d2226d39d132a484f4f7a299fa1b
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-mj59-h3q9-ghfh
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-code-execution-via-mcp-stdio-environment-variables
rules:
  - title: Detect Suspicious OpenClaw Environment Variables
    description: Detects CVE-2026-44995 exploitation — detects process creations with suspicious environment variables indicative of code injection in OpenClaw
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Linux Environment Variables
    description: Detects CVE-2026-44995 exploitation — detects process creations with suspicious environment variables indicative of code injection in OpenClaw on Linux
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw before version 2026.4.20 is vulnerable to an improper environment variable validation in its MCP stdio server configuration. This vulnerability, tracked as CVE-2026-44995, allows attackers to execute arbitrary code on systems running affected versions of OpenClaw. The attack involves crafting malicious workspace configurations that inject dangerous startup variables, such as NODE_OPTIONS, LD_PRELOAD, or BASH_ENV, into spawned MCP server processes. This injection leads to arbitrary code execution when operators initiate sessions using those compromised servers. This poses a significant risk to organizations utilizing OpenClaw, as it can lead to complete system compromise.

## Attack Chain

1.  Attacker crafts a malicious OpenClaw workspace configuration.
2.  The malicious configuration includes specially crafted environment variables such as `NODE_OPTIONS`, `LD_PRELOAD`, or `BASH_ENV`.
3.  An operator unwittingly loads the malicious workspace configuration in OpenClaw.
4.  OpenClaw spawns an MCP stdio server process, inheriting the attacker-controlled environment variables.
5.  The injected environment variables cause the spawned MCP server process to load attacker-supplied code.
6.  Arbitrary code is executed within the context of the MCP server process.
7.  The attacker gains control over the affected system.

## Impact

Successful exploitation of CVE-2026-44995 can lead to arbitrary code execution on the OpenClaw server. An attacker can use this to gain complete control of the system, potentially leading to data theft, system compromise, or denial of service. This vulnerability impacts any organization using OpenClaw versions prior to 2026.4.20.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.20 or later to patch CVE-2026-44995.
*   Implement the Sigma rule `Detect Suspicious OpenClaw Environment Variables` to identify potentially malicious workspace configurations.
*   Monitor process creation events for the use of `NODE_OPTIONS`, `LD_PRELOAD`, or `BASH_ENV` environment variables in OpenClaw MCP stdio server processes.
