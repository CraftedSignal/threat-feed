---
title: OpenClaw Matrix Profile Config Persistence Vulnerability
slug: 2024-01-openclaw-config-persistence
description: A vulnerability in the openclaw npm package before version 2026.4.10 allows unauthorized modification of Matrix profile configurations via the `operator.write` message tool.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - npm
  - vulnerability
  - persistence
vendors:
  - qclaw
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-7jp6-r74r-995q
  - https://github.com/qclaw/openclaw
rules:
  - title: Detect OpenClaw operator.write Message with Profile Modification
    description: Detects suspicious `operator.write` messages potentially attempting to modify Matrix profile configurations in vulnerable OpenClaw versions.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - application
      - nodejs
  - title: Detect OpenClaw version prior to 2026.4.10
    description: Detects OpenClaw versions older than 2026.4.10
    platform: sigma
    severity: medium
    tactics:
      - vulnerability
    data_sources:
      - application
      - nodejs
rules_count: 2
---

A critical vulnerability exists in versions of the `openclaw` npm package prior to 2026.4.10. The vulnerability stems from insufficient access control within the gateway's `operator.write` message-tool paths. These paths inadvertently provide access to Matrix profile persistence functions that are intended to be restricted to administrator-level privileges. This means that attackers could potentially modify sensitive Matrix profile configurations without proper authorization. The vulnerability was addressed in version 2026.4.10 and subsequent releases, with `openclaw@2026.4.14` incorporating the fix. This issue was reported and resolved with contributions from multiple security researchers and sponsors, highlighting its potential impact on affected systems.

## Attack Chain

1. An attacker gains access to a system with the vulnerable `openclaw` package installed.
2. The attacker crafts a malicious `operator.write` message intended to exploit the exposed Matrix profile persistence functionality.
3. The crafted message bypasses intended access controls due to the vulnerability.
4. The malicious message reaches the vulnerable Matrix profile persistence component.
5. The component processes the message without proper authorization checks.
6. The attacker modifies sensitive Matrix profile configurations, such as user permissions or system settings.
7. The modified configuration persists across system restarts due to the compromised persistence mechanism.
8. The attacker leverages the modified profile configuration to escalate privileges or gain unauthorized access to sensitive data.

## Impact

Successful exploitation of this vulnerability could allow attackers to gain unauthorized control over Matrix profile configurations. This could lead to privilege escalation, unauthorized access to sensitive data, and potential disruption of service. While the exact scope of potential victims is unknown, any system running a vulnerable version of the `openclaw` package is at risk. This could impact various sectors relying on the package for their operations.

## Recommendation

*   Immediately upgrade the `openclaw` npm package to version 2026.4.10 or later to remediate the vulnerability.
*   Monitor npm package installations and updates within your environment to detect and prevent the use of vulnerable versions of `openclaw`.
*   Implement strict access controls and input validation on message-tool paths to prevent unauthorized access to sensitive functionalities.
