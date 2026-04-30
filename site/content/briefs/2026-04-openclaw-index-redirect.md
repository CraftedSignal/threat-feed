---
title: OpenClaw NPM Package Vulnerable to Python Package Index Redirection
slug: 2026-04-openclaw-index-redirect
description: The openclaw npm package is vulnerable to Python package-index redirection through host execution due to improper sanitization of `PIP_INDEX_URL` and `UV_INDEX_URL`, affecting versions 2026.3.28 and earlier.
date: "2026-04-02T20:57:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - npm
  - package-index-redirection
  - environment-variable-injection
references:
  - https://github.com/advisories/GHSA-7ggg-pvrf-458v
rules:
  - title: Detect OpenClaw Using Suspicious Index URL
    description: Detects the use of openclaw with potentially malicious PIP_INDEX_URL or UV_INDEX_URL environment variables.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw Execution
    description: Detects execution of openclaw, which should be monitored for suspicious activity given the vulnerability.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `openclaw` npm package, versions 2026.3.28 and earlier, contains a vulnerability that allows for the redirection of Python package-index traffic. This is due to insufficient sanitization of the `PIP_INDEX_URL` and `UV_INDEX_URL` environment variables during host execution. An attacker can potentially exploit this vulnerability to redirect package installation traffic to a malicious index, potentially leading to the installation of compromised packages. The scope of this vulnerability is limited to approved or allowlisted package-management execution paths, mitigating the risk of arbitrary remote execution. Version 2026.3.31 and later contain the fix. The vulnerability was reported by @nexrin.

## Attack Chain

1. An attacker identifies a system using a vulnerable version (<=2026.3.28) of the `openclaw` npm package.
2. The attacker gains access to the system or its environment configuration.
3. The attacker sets either the `PIP_INDEX_URL` or `UV_INDEX_URL` environment variable to point to a malicious Python package index server.
4. The system executes a package installation command (e.g., `pip install <package>`) through `openclaw`.
5. `openclaw`, without proper sanitization, uses the attacker-controlled environment variable when resolving package dependencies.
6. The package manager connects to the malicious index server specified in the `PIP_INDEX_URL` or `UV_INDEX_URL` variable.
7. The attacker serves malicious or backdoored Python packages through the rogue index.
8. The system installs the malicious packages, potentially compromising the system with arbitrary code execution.

## Impact

Successful exploitation of this vulnerability could lead to the installation of malicious Python packages on systems utilizing the vulnerable `openclaw` version. This could result in arbitrary code execution, data theft, or other malicious activities, depending on the contents of the malicious packages. The scope is somewhat limited since only allowlisted execution paths are affected, which reduces the blast radius.

## Recommendation

*   Upgrade the `openclaw` npm package to version 2026.3.31 or later to remediate the vulnerability.
*   Monitor process executions involving `openclaw` and the use of `PIP_INDEX_URL` or `UV_INDEX_URL` environment variables. Deploy the Sigma rule `Detect OpenClaw Using Suspicious Index URL` to detect exploitation attempts.
*   Implement strict allowlisting of package management execution paths to further limit the potential impact.
*   Enable process creation logging to capture command line arguments and environment variables for the `openclaw` process.
