---
title: OpenClaw Improper Access Control Vulnerability (CVE-2026-45006)
slug: 2026-05-openclaw-access-control-bypass
description: OpenClaw before 2026.4.23 contains an improper access control vulnerability (CVE-2026-45006) in the gateway tool's config.apply and config.patch operations, allowing compromised models to write unsafe configuration changes and persist malicious config modifications by bypassing an incomplete denylist.
date: "2026-05-11T18:19:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - access-control
  - configuration-management
  - persistence
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-45006
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45006
  - https://github.com/openclaw/openclaw/commit/bceda6089aa7b3695cc7696b43c61ae3d01bb0ec
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-cwj3-vqpp-pmxr
  - https://www.vulncheck.com/advisories/openclaw-unsafe-config-mutation-via-gateway-tool-denylist-bypass
rules:
  - title: Detect OpenClaw Config Apply Patch
    description: Detects CVE-2026-45006 exploitation — Monitors for calls to config.apply or config.patch operations in OpenClaw gateway tool, potentially indicating attempts to exploit the improper access control vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
rules_count: 1
---

OpenClaw, a tool used for managing and automating complex systems, is vulnerable to an improper access control issue. Specifically, versions before 2026.4.23 of the OpenClaw gateway tool are susceptible to CVE-2026-45006. The vulnerability resides in the `config.apply` and `config.patch` operations, where an incomplete denylist protection can be bypassed. A compromised model, potentially due to a separate vulnerability or misconfiguration, can exploit this flaw to inject unsafe configuration changes. This bypass can allow attackers to persist malicious configuration modifications that impact critical system functions such as command execution, network behavior, credential management, and operator policies. Critically, these modifications survive restarts, indicating a persistent foothold within the affected environment. Defenders should prioritize patching OpenClaw installations to version 2026.4.23 or later to mitigate this risk.

## Attack Chain

1. Initial compromise of an OpenClaw model via an existing vulnerability or compromised credentials.
2. The attacker uses the compromised model to interact with the OpenClaw gateway tool.
3. The attacker crafts malicious configuration changes designed to compromise system functionality.
4. The attacker uses the `config.apply` or `config.patch` operation to apply the crafted configuration changes.
5. The incomplete denylist protection is bypassed, allowing the malicious changes to be written.
6. The malicious configuration changes are persisted to the system.
7. The attacker exploits the modified configuration to execute arbitrary commands or modify network behavior.
8. The attacker achieves persistence, maintaining access even after system restarts, by leveraging the maliciously configured settings.

## Impact

Successful exploitation of CVE-2026-45006 allows attackers to persistently modify critical system configurations within OpenClaw environments. This can lead to unauthorized command execution, manipulation of network settings, credential theft or modification, and alteration of operator policies. The vulnerability could impact organizations relying on OpenClaw for managing and automating their infrastructure, potentially leading to significant operational disruptions and security breaches. The ability to persist malicious configurations even after restarts increases the severity and potential long-term impact of a successful attack.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.23 or later to patch CVE-2026-45006 (see references).
*   Implement strict access controls and monitoring on OpenClaw models to prevent unauthorized modification of configurations.
*   Regularly review OpenClaw configurations for any unexpected or malicious changes to command execution paths, network settings, or credential stores.
*   Deploy the Sigma rule `Detect OpenClaw Config Apply Patch` to identify attempts to exploit this vulnerability by monitoring for calls to the config.apply or config.patch operations.
*   Monitor OpenClaw logs for any unauthorized configuration changes related to command execution, network behavior, or credential management.
