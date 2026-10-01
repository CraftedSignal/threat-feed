---
title: Cross-Site Request Forgery in Lektor Admin API
slug: 2026-10-lektor-csrf
description: Lektor versions 3.3.14 and 3.4.0b15 are vulnerable to CSRF in the admin API, allowing unauthenticated attackers to perform state-changing operations via malicious web pages.
date: "2026-10-01T20:24:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:lektor:lektor:3.3.14:*:*:*:*:*:*:*
  - cpe:2.3:a:lektor:lektor:3.4.0:beta15:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - csrf
  - lfi
vendors:
  - Lektor
products:
  - Lektor (3.3.14, 3.4.0b15)
cves:
  - id: CVE-2026-104059
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104059
rules:
  - title: Detect Suspicious Lektor Admin API Access Without Referer
    description: Detects potentially malicious cross-origin requests to sensitive Lektor admin API endpoints that lack a Referer header, a common indicator of CSRF attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Lektor instances and verify version
      owner: IT Operations
      due: 24h
  mitigation_plan:
    - priority: immediate
      action: Implement strict IP-based access controls for admin endpoints
      owner: IT Operations
      addresses: CVE-2026-104059
---

Lektor versions 3.3.14 and 3.4.0b15 contain a critical cross-site request forgery (CSRF) vulnerability within the admin API blueprint. The application fails to implement essential security controls, including CSRF tokens, Origin and Referer validation, CORS configuration, and Host allowlisting. This oversight allows unauthenticated attackers to trick authenticated administrative users into triggering unintended, state-changing actions by luring them to a malicious web page. Successful exploitation enables an attacker to perform arbitrary file writes, delete records, clear build outputs, and initiate deployment publication. Furthermore, through DNS rebinding techniques, an attacker may bypass browser-based protections to access sensitive read endpoints, resulting in unauthorized data disclosure. This vulnerability poses a high risk to the integrity and availability of Lektor-based projects.

## Impact

Successful exploitation of CVE-2026-104059 allows unauthenticated remote attackers to compromise the administrative functions of Lektor instances. Impact includes loss of data confidentiality through unauthorized read access, and loss of integrity and availability through arbitrary file writes, deletion of records, and destruction of build environments.

## Recommendation

Prioritized actions for security teams:
- Identify and inventory all internet-facing instances of Lektor.
- Implement strict network-level access control lists (ACLs) or authentication proxies (e.g., OAuth2-proxy) in front of the Lektor admin panel as a compensatory control until patches are applied.
- Monitor web server logs for suspicious requests to admin endpoints (/admin/api/newattachment, /admin/api/deleterecord, /admin/api/build, /admin/api/clean, /admin/api/publish) that lack a valid Referer or Origin header, or originate from untrusted cross-origin sources.
