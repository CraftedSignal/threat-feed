---
title: OpenClaw Incomplete Host Environment Variable Sanitization Vulnerability (CVE-2026-41387)
slug: 2026-04-openclaw-env-vuln
description: OpenClaw before 2026.3.22 is vulnerable to incomplete host environment variable sanitization, allowing attackers to redirect package resolution or runtime bootstrap to attacker-controlled infrastructure and execute trojanized content.
date: "2026-04-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - vulnerability
  - supply-chain
  - environment-variable
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41387
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41387
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-j7p2-qcwm-94v4
  - https://www.vulncheck.com/advisories/openclaw-supply-chain-redirection-via-incomplete-host-environment-sanitization
rules:
  - title: Detect Package Manager Redirection via Environment Variables
    description: Detects attempts to override package manager settings using environment variables, potentially indicating an exploit of CVE-2026-41387.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Network Connection During Package Installation
    description: Detects network connections to unusual domains during package installation processes, which may indicate package redirection.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.22 contain a vulnerability related to incomplete sanitization of host environment variables. This flaw, found in `host-env-security-policy.json` and `host-env-security.ts`, allows for the overriding of package manager environment settings. An attacker can leverage this vulnerability to redirect approved execution requests, manipulating the package resolution process or the runtime bootstrap. By doing so, they can point these processes to attacker-controlled infrastructure. This enables the execution of trojanized content, potentially leading to supply chain attacks or arbitrary code execution within the affected environment. The vulnerability is identified as CVE-2026-41387.

## Attack Chain

1.  Attacker identifies an OpenClaw instance running a version prior to 2026.3.22.
2.  Attacker crafts malicious environment variables designed to override the package manager's default settings.
3.  The attacker triggers an approved execution request within the OpenClaw environment.
4.  Due to the incomplete sanitization, the attacker-controlled environment variables are used by the package manager.
5.  The package manager is redirected to the attacker's infrastructure for package resolution or runtime bootstrap.
6.  The attacker's infrastructure serves trojanized content disguised as legitimate packages or runtime components.
7.  OpenClaw executes the trojanized content, granting the attacker initial access to the system.

## Impact

Successful exploitation of CVE-2026-41387 can lead to the execution of arbitrary code within the OpenClaw environment. This can result in compromised systems, data breaches, or supply chain attacks. Due to the nature of package management redirection, the impact could extend beyond the initial target, affecting other systems relying on the compromised OpenClaw instance. The vulnerability has a CVSS v3.1 score of 7.8, indicating a high severity.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.22 or later to remediate the vulnerability described in CVE-2026-41387.
*   Implement stricter input validation on environment variables used by OpenClaw, focusing on package manager settings, to prevent redirection attacks.
*   Monitor network traffic for connections to unusual or untrusted domains during package resolution or runtime bootstrap, as this may indicate an attempted redirection attack.
