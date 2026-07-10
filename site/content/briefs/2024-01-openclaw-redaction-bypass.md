---
title: OpenClaw Configuration Redaction Bypass Vulnerability
slug: 2024-01-openclaw-redaction-bypass
description: A vulnerability in the openclaw npm package before version 2026.4.14 allows authenticated clients with config read access to receive unredacted secrets due to bypasses in `sourceConfig` and `runtimeConfig` alias fields.
date: "2024-01-18T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - npm
  - openclaw
  - vulnerability
  - redaction-bypass
vendors:
  - openclaw
products:
  - openclaw
references:
  - https://github.com/advisories/GHSA-8372-7vhw-cm6q
rules:
  - title: Detect OpenClaw Config Read Access
    description: Detects requests for sensitive configuration data within OpenClaw, which might be indicative of exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Version Check via User-Agent
    description: This rule detects potential version checks for vulnerable OpenClaw instances based on the User-Agent string.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1592
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `openclaw` npm package, versions prior to 2026.4.14, contains a vulnerability that could lead to the exposure of sensitive information. An authenticated gateway client with the ability to read configurations might receive unredacted secrets, such as provider API keys, gateway authentication material, and channel credentials. The vulnerability stems from alias fields (`sourceConfig` and `runtimeConfig`) that bypass the redaction process normally applied to configuration data. Successful exploitation would allow unauthorized access to sensitive resources and potentially compromise the security of systems relying on the `openclaw` package. This issue was reported by @zsxsoft, with sponsorship from @KeenSecurityLab and @qclawer, and has been patched in version 2026.4.14.

## Attack Chain

1. An attacker authenticates as a gateway client with config read access.
2. The client requests configuration data from the `openclaw` package.
3. The vulnerable `openclaw` version processes the request.
4. The `config.get` function is called to retrieve configuration parameters.
5. Redaction is applied to the `resolved` and `config` fields.
6. However, the `sourceConfig` and `runtimeConfig` alias fields are not correctly redacted.
7. The client receives the configuration data, including the unredacted secrets present in the `sourceConfig` or `runtimeConfig` fields.
8. The attacker extracts sensitive information (API keys, credentials) from the unredacted data.

## Impact

Successful exploitation of this vulnerability could lead to the exposure of sensitive credentials, including API keys, gateway authentication material, and channel credentials. An attacker could leverage these credentials to gain unauthorized access to internal systems and resources. The number of affected installations is unknown, but all deployments using `openclaw` versions prior to 2026.4.14 are vulnerable. The npm package ecosystem is broadly used, so the impact could be significant.

## Recommendation

*   Upgrade the `openclaw` npm package to version 2026.4.14 or later to remediate the vulnerability as described in the advisory.
*   Monitor application logs for unusual access patterns to configuration data that may indicate exploitation attempts.
*   Implement strict access control policies to limit which clients can request configuration data, reducing the attack surface.
*   Consider using a secrets management solution to further protect sensitive credentials.
