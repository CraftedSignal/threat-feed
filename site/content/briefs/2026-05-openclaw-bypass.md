---
title: OpenClaw Gateway Config Mutation Guard Bypass (CVE-2026-45001)
slug: 2026-05-openclaw-bypass
description: OpenClaw before 2026.4.20 contains a guard bypass vulnerability in the agent-facing gateway config.patch and config.apply endpoints, allowing a prompt-injected model with access to the owner-only gateway tool to persist unauthorized changes to protected operator settings.
date: "2026-05-11T18:18:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - vulnerability
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-45001
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45001
  - https://github.com/openclaw/openclaw/commit/fe30b31a97a917ecc6e92f6c85378b6b20352422
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-7jm2-g593-4qrc
  - https://www.vulncheck.com/advisories/openclaw-gateway-config-mutation-guard-bypass-via-agent-tool-access
rules:
  - title: Detect OpenClaw Unauthorized Configuration Change via config.patch/config.apply
    description: Detects CVE-2026-45001 exploitation — HTTP POST to config.patch or config.apply endpoints indicating potential unauthorized configuration changes
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect OpenClaw Gateway Tool Access
    description: Detects access to the OpenClaw gateway tool, which is required for exploiting CVE-2026-45001.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

OpenClaw before version 2026.4.20 is vulnerable to a guard bypass in its agent-facing gateway. The vulnerability resides in the `config.patch` and `config.apply` endpoints. This flaw allows a prompt-injected model that has access to the owner-only gateway tool to bypass intended restrictions. By exploiting this vulnerability, an attacker can modify operator-trusted settings, which includes sandbox policy, plugin enablement, gateway authentication and TLS configuration, hook routing, MCP server configuration, SSRF policy, and filesystem hardening measures. This bypass could lead to significant compromise of the OpenClaw environment, enabling unauthorized access and control.

## Attack Chain

1. An attacker gains initial access to an OpenClaw system.
2. The attacker identifies a prompt injection vulnerability within a model accessible to the gateway tool.
3. The attacker crafts a malicious prompt that exploits the injection vulnerability.
4. The attacker uses the compromised model to access the owner-only gateway tool.
5. The attacker leverages the `config.patch` or `config.apply` endpoints to submit unauthorized configuration changes.
6. The bypassed guard allows the unauthorized configuration changes to persist.
7. The attacker modifies critical settings such as sandbox policy, plugin enablement, or gateway authentication.
8. The attacker establishes persistent control over the OpenClaw environment, potentially leading to data exfiltration or further attacks.

## Impact

Successful exploitation of CVE-2026-45001 can lead to a complete compromise of the OpenClaw environment. Attackers can modify security policies, enable malicious plugins, bypass authentication mechanisms, and reconfigure server settings. The consequences include unauthorized access to sensitive data, the introduction of malicious functionality, and the potential for lateral movement to other systems.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.20 or later to patch CVE-2026-45001.
*   Implement the Sigma rule "Detect OpenClaw Unauthorized Configuration Change via config.patch/config.apply" to identify potential exploitation attempts based on HTTP endpoint access.
*   Enforce strict access controls to the owner-only gateway tool, limiting access to authorized personnel only.
