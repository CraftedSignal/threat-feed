---
title: '@fastify/middie Middleware Bypass Vulnerability via Duplicate Slashes'
slug: 2024-01-29-fastify-middie-bypass
description: '`@fastify/middie` versions 9.3.1 and earlier are vulnerable to middleware bypass via URLs with duplicate leading slashes due to improper handling of the deprecated `ignoreDuplicateSlashes` option, potentially allowing unauthorized access to protected resources.'
date: "2024-01-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - fastify
  - middie
  - middleware-bypass
  - vulnerability
  - defense-evasion
vendors:
  - Fastify
products:
  - Fastify
  - '@fastify/middie'
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-2880
    cvss: 9.1
    epss: 0.00227
references:
  - https://github.com/advisories/GHSA-v9ww-2j6r-98q6
rules:
  - title: Detect Suspicious URL Access via Duplicate Slashes
    description: Detects HTTP requests with URLs containing duplicate leading slashes, potentially indicating an attempt to bypass middleware in vulnerable Fastify applications.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP 404 to paths with leading slashes
    description: Detects HTTP 404 status code for a path that starts with leading slashes. This may indicate a failed attempt to exploit the Fastify Middie vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists in the `@fastify/middie` package, a middleware engine for the Fastify web framework. Specifically, versions 9.3.1 and earlier fail to properly handle the deprecated top-level `ignoreDuplicateSlashes` option. This option, intended to normalize duplicate slashes in URLs, is only read from the `routerOptions` configuration, leading to a discrepancy where Fastify's router normalizes slashes but middie does not.  The vulnerability allows attackers to bypass middleware protections by crafting URLs with duplicate leading slashes (e.g., `//admin/secret`). This only impacts applications still using the deprecated top-level configuration style (`fastify({ ignoreDuplicateSlashes: true })`). This issue is distinct from CVE-2026-2880 (GHSA-8p85-9qpw-fwgw) and was addressed in version 9.2.0. Defenders should prioritize patching or migrating to the supported `routerOptions` configuration.

## Attack Chain

1.  The attacker identifies a Fastify application using `@fastify/middie` version 9.3.1 or earlier and employing the deprecated top-level `ignoreDuplicateSlashes` option.
2.  The attacker crafts a malicious HTTP request with a URL containing duplicate leading slashes (e.g., `//admin/secret`).
3.  Fastify's router normalizes the URL, removing the duplicate slashes before routing.
4.  However, `@fastify/middie` does not properly handle the `ignoreDuplicateSlashes` option from the top-level configuration.
5.  Due to the normalization gap, the request bypasses middleware intended to protect the `/admin/secret` route.
6.  The request reaches the vulnerable route, potentially exposing sensitive information or functionality.
7.  The application processes the request without proper authentication or authorization checks due to the bypassed middleware.
8.  The attacker gains unauthorized access to protected resources, leading to data leakage or privilege escalation.

## Impact

Successful exploitation of this vulnerability can lead to unauthorized access to sensitive resources within affected Fastify applications. The number of victims depends on the prevalence of the vulnerable configuration. Sectors particularly at risk include organizations using Fastify for web application development without adhering to security best practices.  If the attack succeeds, attackers could gain access to administrative interfaces, confidential data, or other protected resources, potentially leading to data breaches, service disruption, or other adverse outcomes.

## Recommendation

*   Upgrade to `@fastify/middie` version 9.3.2 or later to remediate the vulnerability (reference: Affected Packages).
*   Migrate from the deprecated top-level `ignoreDuplicateSlashes: true` configuration to `routerOptions: { ignoreDuplicateSlashes: true }` (reference: Workarounds).
*   Deploy the Sigma rule "Detect Suspicious URL Access via Duplicate Slashes" to identify potential exploitation attempts (reference: rules).
*   Monitor web server logs for HTTP requests with URLs containing duplicate leading slashes targeting sensitive endpoints (reference: webserver logs).
