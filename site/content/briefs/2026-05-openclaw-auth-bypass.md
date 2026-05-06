---
title: OpenClaw Bearer Token Validation Bypass via Stale SecretRef Resolution
slug: 2026-05-openclaw-auth-bypass
description: OpenClaw before 2026.4.15 captures resolved bearer-auth configuration at startup, allowing revoked tokens to remain valid after SecretRef rotation, leading to unauthorized gateway access via stale bearer tokens.
date: "2026-05-06T20:16:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - credential-access
  - vulnerability
vendors:
  - OpenClaw
products:
  - OpenClaw
  - OpenClaw Gateway
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-43585
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43585
  - https://github.com/openclaw/openclaw/commit/acd4e0a32f12e1ad85f3130f63b42443ce90f094
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-xmxx-7p24-h892
  - https://www.vulncheck.com/advisories/openclaw-bearer-token-validation-bypass-via-stale-secretref-resolution
rules:
  - title: Detect OpenClaw Authentication Bypass via Stale Token
    description: Detects potential exploitation of OpenClaw authentication bypass by monitoring for bearer token usage after SecretRef rotation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw WebSocket Connection with Bearer Token
    description: Detects WebSocket connections potentially using stale bearer tokens in OpenClaw.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

OpenClaw, a gateway application, is vulnerable to an authentication bypass issue. Specifically, versions prior to 2026.4.15 exhibit a flaw where the bearer-auth configuration is resolved only at startup. This means that after a SecretRef rotation (when tokens are intended to be revoked), the gateway's HTTP and WebSocket handlers do not re-resolve authentication per request. Consequently, an attacker could potentially leverage rotated-out bearer tokens to gain unauthorized access to the gateway. This vulnerability allows an attacker to bypass authentication mechanisms and gain unauthorized access to resources protected by the OpenClaw gateway.

## Attack Chain

1.  An attacker obtains a valid bearer token for OpenClaw gateway access.
2.  The organization rotates the SecretRef, which should invalidate the attacker's token.
3.  OpenClaw gateway, due to the vulnerability, does not re-resolve authentication per-request.
4.  The attacker attempts to access a protected resource using the previously valid, now rotated-out bearer token via an HTTP or WebSocket request.
5.  The gateway, still using the old configuration, incorrectly validates the token.
6.  The attacker gains unauthorized access to the protected resource.
7.  The attacker performs actions they are not authorized to perform, potentially exfiltrating data or modifying configurations.

## Impact

Successful exploitation of CVE-2026-43585 allows attackers to bypass authentication and gain unauthorized access to resources protected by the OpenClaw gateway. This can lead to the exposure of sensitive data, unauthorized modification of configurations, and other malicious activities. The severity is rated as high with a CVSS v3.1 score of 8.1, indicating significant potential for damage. The number of victims and specific sectors targeted are currently unknown.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.15 or later to patch CVE-2026-43585.
*   Monitor webserver logs for HTTP and WebSocket requests using bearer tokens after SecretRef rotation; deploy the Sigma rule `Detect OpenClaw Authentication Bypass via Stale Token` to detect potential exploitation attempts.
*   Implement robust monitoring and alerting for unauthorized access attempts to protected resources to detect post-exploitation activity.
