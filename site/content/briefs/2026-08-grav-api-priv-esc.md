---
title: Privilege Escalation via Improper API Scope Validation in Grav Plugin
slug: 2026-08-grav-api-priv-esc
description: The grav-plugin-api plugin for Grav fails to validate API key scope hierarchy, allowing low-privileged users to mint unrestricted administrative keys via the createApiKey endpoint.
date: "2026-08-14T14:11:31Z"
lastmod: "2026-08-14T16:12:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - web-vulnerability
vendors:
  - Grav
products:
  - grav-plugin-api
  - Grav Plugin API
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker holding a minimal-scope API key on a super account can submit an empty scopes array to mint an unscoped, full-access super key, bypassing scope restrictions.
    confidence_band: high
cves:
  - id: CVE-2026-72826
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72826
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72828
updates:
  - at: "2026-08-14T16:12:01Z"
    level: L2
    summary: added coverage for Grav Plugin API
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72828
---

The Grav CMS plugin 'grav-plugin-api' (prior to version 1.0.13) contains a critical vulnerability regarding the creation of API keys. The 'createApiKey' function fails to enforce a security constraint that requires newly generated key scopes to be a subset of the caller's own permissions. Because the 'requireApiKeyPermission' function only checks for baseline 'api.access' permissions, an authenticated user possessing a low-privileged API key can send a specially crafted request to 'createApiKey'. By manipulating the request body to submit an empty scopes array, the attacker can successfully mint a new API key with elevated, unrestricted access. This administrative-level key can then be used to modify Grav configuration files or deploy malicious assets, leading to Remote Code Execution (RCE) on the underlying server. Organizations using Grav CMS with the API plugin enabled are at high risk of full platform compromise if they allow external API key generation.

## Impact

Successful exploitation results in full administrative privilege escalation within the Grav CMS application. This enables attackers to overwrite system configurations, modify site content, and execute arbitrary code. The vulnerability poses a critical risk to any infrastructure hosting Grav, as it bypasses intended authorization boundaries for API-based management.

## Recommendation

1. Upgrade the 'grav-plugin-api' plugin to version 1.0.13 or later immediately to patch the missing scope subset validation.
2. Review existing API keys within the Grav administration panel for any anomalous keys with excessive or unexpected scopes.
3. Restrict access to the API creation endpoint to trusted administrative users only until the patch can be applied.
4. Audit web server logs for high-frequency or unauthorized calls to the 'createApiKey' endpoint that coincide with unusual administrative account activities.
