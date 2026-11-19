---
brief_id: brief-2026-05-litellm-privesc
event_id: brief-2026-05-litellm-privesc
revision: 3
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:34d08e70f368b0b6b6ded0197d2acc9505d2c0af96a41f8cc94b060913158b2a
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
  - revision: 3
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:f0ddedc6b6ec7bcbc242bcc00238e137c39e450e9415bfb184b2b07f9297b71d
    summary: exploited:true; KEV CVE-2026-40217; KEV CVE-2026-42271
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - lastmod
      - poc_references
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: LiteLLM Privilege Escalation via API Key Creation (CVE-2026-47101)
slug: 2026-05-litellm-privesc-b8966cad
description: LiteLLM versions prior to 1.83.14 allow an authenticated internal user to create API keys that bypass role-based access controls, potentially leading to full privilege escalation to proxy_admin due to a lack of verification of specified routes within the user's own permissions (CVE-2026-47101).
date: "2026-05-21T21:18:27Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-06-08T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:litellm:litellm:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=B89C55B6-BB97-51C5-8FE2-2043E73BE1A8&utm_source=rss&utm_medium=rss
tags:
  - privilege-escalation
  - vulnerability
  - CVE-2026-47101
vendors:
  - Berri AI
  - BerriAI
  - LiteLLM
products:
  - LiteLLM
  - LiteLLM < 1.83.14
product_versions:
  - product: LiteLLM
    range: < v1.83.14-stable
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-47101
    cvss: 8.8
    epss: 0.00459
    kev_status: unknown
  - id: CVE-2026-47102
    cvss: 8.8
    epss: 0.00378
    kev_status: unknown
  - id: CVE-2026-40217
    cvss: 8.8
    epss: 0.00709
    kev: true
    kev_status: "true"
  - id: CVE-2026-42271
    cvss: 8.8
    epss: 0.53701
    kev: true
    kev_status: "true"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47101
  - https://sploitus.com/exploit?id=B89C55B6-BB97-51C5-8FE2-2043E73BE1A8&utm_source=rss&utm_medium=rss
  - https://thehackernews.com/2026/06/litellm-vulnerability-chain-lets-low.html
rules:
  - title: Detect API Key Creation with Elevated Permissions
    description: Detects CVE-2026-47101 — API key creation with admin-only routes by internal users, indicating a privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-47101
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect API Access Using Newly Created Key
    description: Detects API access to admin-only routes using a recently created API key, potentially indicating a privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-47101
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-05-25T10:01:47Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
  - at: "2026-06-15T17:11:54Z"
    level: L2
    summary: added CVE-2026-40217 +2
    sources:
      - the-hacker-news
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-40217; KEV CVE-2026-42271
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

LiteLLM versions prior to 1.83.14 are vulnerable to a privilege escalation flaw. An authenticated `internal_user` can create API keys with permissions exceeding their assigned roles. The vulnerability exists because the `allowed_routes` field is stored without validating that the specified routes are within the user's authorized permissions. By creating a key with access to `admin-only` routes, the attacker can bypass role-based access controls and elevate their privileges to `proxy_admin`. This allows the attacker to perform actions normally restricted to administrators, such as accessing sensitive data, modifying configurations, or disrupting services. Defenders should upgrade to version 1.83.14 or later to mitigate this vulnerability.

## Attack Chain

1. Attacker authenticates as an `internal_user`.
2. Attacker initiates the API key creation process.
3. Attacker specifies `allowed_routes` that include `admin-only` routes.
4. The system stores the `allowed_routes` without proper validation against the user's permissions.
5. Attacker obtains the newly created API key.
6. Attacker uses the API key to access the `admin-only` routes.
7. The system incorrectly authorizes the request based on the API key's `allowed_routes`, bypassing role-based access controls.
8. Attacker successfully executes actions normally restricted to `proxy_admin`, achieving full privilege escalation.

## Impact

Successful exploitation of this vulnerability allows an attacker to escalate their privileges from `internal_user` to `proxy_admin`. This grants the attacker full control over the LiteLLM instance, potentially leading to unauthorized access to sensitive data, modification of system configurations, and disruption of services. The severity is high due to the potential for complete system compromise and the ease of exploitation once the initial authentication is achieved.

## Recommendation

*   Upgrade LiteLLM to version 1.83.14 or later to patch CVE-2026-47101.
*   Implement the "Detect API Key Creation with Elevated Permissions" Sigma rule to identify attempts to create API keys with unauthorized routes.
*   Implement the "Detect API Access Using Newly Created Key" Sigma rule to identify unauthorized API access using newly created API keys.
