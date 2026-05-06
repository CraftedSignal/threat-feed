---
title: OpenClaw Improper Environment Variable Handling Vulnerability
slug: 2026-05-openclaw-env-override
description: OpenClaw before 2026.4.20 is vulnerable to improper environment variable namespace reservation, allowing attackers to override critical runtime variables via workspace dotenv files.
date: "2026-05-06T20:16:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - environment_variable_override
  - code_execution
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
cves:
  - id: CVE-2026-44114
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44114
  - https://github.com/openclaw/openclaw/commit/018494fa3ebb9145112e68b56fe1cb2e9f9a9ed6
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-hxvm-xjvf-93f3
  - https://www.vulncheck.com/advisories/openclaw-environment-variable-namespace-collision-via-workspace-dotenv
rules:
  - title: Detect OpenClaw Environment Variable Overrides
    description: Detects processes attempting to set environment variables with the OPENCLAW_ prefix, potentially indicating an attempted override.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - process_creation
      - windows
  - title: Detect OpenClaw Git Directory Manipulation
    description: Detects processes that utilize a modified git directory, potentially indicating an attempt to use a malicious repository.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw versions prior to 2026.4.20 are susceptible to an environment variable namespace collision vulnerability. This flaw stems from the application's failure to properly reserve the `OPENCLAW_` runtime-control environment namespace within workspace dotenv files. By crafting malicious workspaces, attackers can set variables like `OPENCLAW_GIT_DIR` to manipulate OpenClaw runtime behavior during critical operations, such as source updates and installer workflows. This vulnerability allows for the potential hijacking of trusted OpenClaw runtime processes.

## Attack Chain

1.  Attacker crafts a malicious workspace containing a dotenv file.
2.  The dotenv file includes environment variables prefixed with `OPENCLAW_`, such as `OPENCLAW_GIT_DIR`.
3.  The victim user imports or uses the attacker-controlled workspace in OpenClaw.
4.  OpenClaw loads the dotenv file, inadvertently overriding its own runtime configuration.
5.  During a source-update operation, OpenClaw uses the attacker-controlled `OPENCLAW_GIT_DIR` to locate the Git repository.
6.  The attacker redirects OpenClaw to a malicious Git repository under their control.
7.  OpenClaw executes commands from the attacker's malicious Git repository, leading to code execution.

## Impact

Successful exploitation allows attackers to execute arbitrary code within the context of the OpenClaw application. This could lead to the compromise of the user's system, data exfiltration, or further malicious activities. Given the potentially widespread use of OpenClaw in development environments, this vulnerability poses a significant risk to organizations using affected versions.

## Recommendation

*   Upgrade to OpenClaw version 2026.4.20 or later to remediate the vulnerability (CVE-2026-44114).
*   Implement file integrity monitoring on workspace dotenv files to detect unauthorized modifications.
*   Deploy the Sigma rule `Detect OpenClaw Environment Variable Overrides` to identify suspicious processes modifying OpenClaw's runtime behavior.
