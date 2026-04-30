---
title: OpenClaw Privilege Escalation via Trusted Proxy Authentication (CVE-2026-41404)
slug: 2026-04-openclaw-privilege-escalation
description: OpenClaw before 2026.3.31 contains an incomplete scope-clearing vulnerability in trusted-proxy authentication mode that allows operator.admin privilege escalation by declaring operator scopes on non-Control-UI clients.
date: "2026-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - authentication
  - cve-2026-41404
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41404
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41404
  - https://github.com/openclaw/openclaw/commit/8b88b927cb0747ad24d95b07d35682bf85dc5b0e
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-g374-mggx-p6xc
  - https://www.vulncheck.com/advisories/openclaw-operator-admin-privilege-escalation-via-trusted-proxy-authentication
rules:
  - title: Detect OpenClaw Unauthorized Scope Declaration
    description: Detects attempts to declare operator scopes on non-Control-UI clients in OpenClaw, potentially leading to privilege escalation (CVE-2026-41404).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Admin Privilege Use After Potential Escalation
    description: Detects the use of admin privileges in OpenClaw after a potential privilege escalation via scope declaration.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.3.31 is vulnerable to a privilege escalation flaw within its trusted-proxy authentication mechanism. This vulnerability, identified as CVE-2026-41404, stems from an incomplete scope clearing process. The core issue lies in the ability for attackers to declare operator scopes on clients that are not part of the Control-UI. This leads to a situation where these self-declared scopes are erroneously persisted on authentication paths that bear identity. This allows an attacker to escalate their privileges to operator.admin, effectively gaining administrative control over the OpenClaw instance. This poses a significant risk to the confidentiality, integrity, and availability of systems relying on OpenClaw for authentication and authorization.

## Attack Chain

1. Attacker identifies an OpenClaw instance using trusted-proxy authentication mode.
2. The attacker crafts a request to a non-Control-UI client, declaring operator scopes within the authentication header.
3. OpenClaw's incomplete scope clearing mechanism fails to remove the attacker-declared operator scopes.
4. The attacker authenticates through an identity-bearing authentication path.
5. Due to the persisted operator scopes, the attacker is granted elevated privileges.
6. The attacker leverages the escalated operator.admin privileges to perform unauthorized actions. This could include modifying configurations, accessing sensitive data, or disrupting services.
7. The attacker maintains persistent access by creating new administrator accounts.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain operator.admin privileges within the OpenClaw environment. This can lead to complete control over the affected OpenClaw instance. Consequences include unauthorized access to sensitive data, modification of system configurations, and disruption of services. The severity is compounded by the fact that the vulnerability exists in the authentication mechanism, potentially affecting all users and systems relying on OpenClaw for access control.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to patch CVE-2026-41404.
*   Implement strict input validation on authentication headers to prevent the declaration of unauthorized scopes.
*   Deploy the Sigma rule `Detect OpenClaw Unauthorized Scope Declaration` to monitor for suspicious authentication requests.
*   Review and audit existing OpenClaw configurations to identify and remove any unauthorized operator scopes.
*   Monitor logs for successful logins with unexpected admin privileges.
