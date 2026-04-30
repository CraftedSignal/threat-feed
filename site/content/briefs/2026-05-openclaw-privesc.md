---
title: OpenClaw Incomplete Scope Clearing Allows Privilege Escalation
slug: 2026-05-openclaw-privesc
description: An incomplete fix in OpenClaw versions 2026.3.28 and earlier allows for operator.admin privilege escalation via trusted-proxy authentication mode, which is fixed in version 2026.3.31.
date: "2026-04-03T03:06:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-g374-mggx-p6xc
rules:
  - title: Detect OpenClaw operator.admin Escalation via Trusted Proxy
    description: Detects potential privilege escalation attempts in OpenClaw by monitoring for unauthorized access attempts to sensitive API endpoints after trusted proxy authentication.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Failed Admin Access after Trusted Proxy Auth
    description: Detects potential failed privilege escalation attempts in OpenClaw by monitoring for failed access attempts to sensitive API endpoints after trusted proxy authentication (may indicate reconnaissance).
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A high-severity vulnerability exists in the OpenClaw npm package, specifically affecting versions 2026.3.28 and earlier. This vulnerability arises from an incomplete fix related to scope clearing within the trusted-proxy authentication mode. The flaw allows attackers to escalate their privileges to operator.admin, potentially gaining unauthorized access to sensitive data or system functionalities. The vulnerability was reported by @north-echo and patched in version 2026.3.31, with the fix committed on March 30, 2026. This issue is critical for organizations utilizing OpenClaw with trusted-proxy authentication, as it could lead to significant security breaches. Defenders should prioritize upgrading to version 2026.3.31 or later to mitigate this risk.

## Attack Chain

1.  Attacker identifies an OpenClaw instance running a vulnerable version (<=2026.3.28) using trusted-proxy authentication.
2.  Attacker gains initial access with limited privileges, potentially via compromised credentials or another vulnerability.
3.  Attacker authenticates via the trusted proxy, declaring a set of operator scopes.
4.  Due to the incomplete scope clearing, the attacker's declared operator scopes are not properly sanitized by the system.
5.  The system incorrectly grants the attacker elevated privileges associated with the self-declared operator scopes.
6.  Attacker exploits the elevated operator.admin privileges to access restricted resources or functionalities.
7.  Attacker performs unauthorized actions, such as data modification, configuration changes, or lateral movement within the system.

## Impact

Successful exploitation of this vulnerability allows an attacker to escalate their privileges to operator.admin within the OpenClaw environment. This could lead to unauthorized access to sensitive data, modification of critical system configurations, and potential disruption of services. The impact is especially significant for organizations that rely on OpenClaw for critical operations and have not yet upgraded to the patched version. The attacker could leverage the escalated privileges to perform a wide range of malicious activities, potentially compromising the entire system.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to remediate the vulnerability (Affected Packages / Versions).
*   Monitor OpenClaw logs for suspicious activity related to trusted-proxy authentication and privilege escalation (logsource: "webserver", product: "linux").
*   Implement strict access controls and regularly review user permissions to minimize the impact of potential privilege escalation attacks.
*   Deploy the Sigma rule provided below to detect potential exploitation attempts targeting this vulnerability.
