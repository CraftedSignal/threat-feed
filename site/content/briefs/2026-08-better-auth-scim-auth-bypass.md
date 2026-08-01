---
title: Authorization Bypass Vulnerability in better-auth SCIM
slug: 2026-08-better-auth-scim-auth-bypass
description: An authorization bypass vulnerability in better-auth SCIM (CVE-2026-67331) allows authenticated users to manage and manipulate SCIM providers belonging to other users due to missing owner-binding checks.
date: "2026-08-01T13:54:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-67331
  - authorization-bypass
  - scim
  - better-auth
vendors:
  - better-auth
products:
  - scim
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The vulnerability allows authenticated users to manage other users' providers and regenerate SCIM bearer tokens.
    confidence_band: high
cves:
  - id: CVE-2026-67331
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67331
  - https://github.com/better-auth/better-auth/security/advisories/GHSA-j8v8-g9cx-5qf4
  - https://www.vulncheck.com/advisories/better-auth-scim-before-beta-4-authorization-bypass
---

The better-auth SCIM package (versions 1.5.0 through 1.6.x) contains a critical authorization flaw tracked as CVE-2026-67331. The vulnerability stems from the application's failure to properly bind non-organization SCIM providers to the specific user account that created them. By default, the system assumes global accessibility for these provider objects, which results in an insecure direct object reference (IDOR) or similar authorization bypass condition. 

This issue allows any authenticated user within the application to perform administrative actions on SCIM providers owned by other users. The impact is significant, as an attacker can list, modify, or delete existing providers, invalidate legitimate SCIM bearer tokens, and generate new tokens under the context of the victim's provider configuration. This effectively permits an attacker to perform account takeover or unauthorized data synchronization by intercepting or manipulating SCIM API traffic. Organizations using affected versions are advised to upgrade to 1.7.0-beta.4 or later immediately.

## Impact

Successful exploitation allows unauthorized users to fully control the SCIM integration lifecycle of other users within the platform. This leads to the compromise of identity synchronization processes, potential unauthorized provisioning or deprovisioning of accounts, and the ability to exfiltrate or modify sensitive identity data transmitted through SCIM. The vulnerability has a CVSS v3.1 base score of 8.3, reflecting the high risk to confidentiality and integrity in enterprise environments relying on SCIM for user lifecycle management.

## Recommendation

- Upgrade the better-auth SCIM package to version 1.7.0-beta.4 or higher to resolve the authorization logic flaw documented in CVE-2026-67331.
- Audit existing SCIM provider configurations in your environment to identify any unauthorized provider objects or unexpected token changes.
- Review web access logs for anomalous API activity directed at SCIM endpoints, specifically looking for repeated modifications of token resources by non-administrative users.
