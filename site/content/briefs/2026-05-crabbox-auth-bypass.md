---
title: Crabbox Authentication Bypass via Header Spoofing (CVE-2026-8621)
slug: 2026-05-crabbox-auth-bypass
description: Crabbox prior to v0.12.0 contains an authentication bypass vulnerability (CVE-2026-8621) that allows non-admin shared-token callers to impersonate other owners or organizations by spoofing identity headers, granting unauthorized access to lease operations.
date: "2026-05-14T19:18:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - header-spoofing
  - cve-2026-8621
vendors:
  - openclaw
products:
  - Crabbox < v0.12.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8621
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8621
  - https://github.com/openclaw/crabbox/commit/b657323f1d1c954cefc8444571fa6c45a8896e7f
  - https://github.com/openclaw/crabbox/pull/70
  - https://github.com/openclaw/crabbox/releases/tag/v0.12.0
  - https://www.vulncheck.com/advisories/crabbox-authentication-bypass-via-header-spoofing
rules:
  - title: Detect Crabbox Authentication Bypass Attempt via Spoofed Headers
    description: Detects CVE-2026-8621 exploitation attempt — monitors for HTTP requests containing both `X-Crabbox-Owner` and `X-Crabbox-Org` headers, indicating potential header spoofing for authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Crabbox Authentication Bypass Attempt via HTTP Method
    description: Detects CVE-2026-8621 exploitation attempt — monitors for HTTP POST or PUT requests containing both `X-Crabbox-Owner` and `X-Crabbox-Org` headers, as this may indicate an attempt to modify data with spoofed credentials.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Crabbox, a currently unspecified software, before version v0.12.0, is vulnerable to an authentication bypass. This flaw, identified as CVE-2026-8621, allows attackers using non-admin shared tokens to impersonate other owners or organizations. By injecting malicious `X-Crabbox-Owner` and `X-Crabbox-Org` headers, attackers can bypass authorization checks. This vulnerability was reported on May 14, 2026, and it impacts any Crabbox installations running versions prior to the fix in v0.12.0. Successful exploitation allows unauthorized access to owner/org-scoped lease operations belonging to victim accounts, leading to potential data breaches or service disruption.

## Attack Chain

1.  Attacker obtains a non-admin shared token for a Crabbox instance prior to v0.12.0.
2.  Attacker crafts a malicious HTTP request targeting owner/org-scoped lease operations.
3.  The attacker injects `X-Crabbox-Owner` and `X-Crabbox-Org` headers into the HTTP request, spoofing the identity of a victim owner or organization.
4.  The attacker authenticates the request using the compromised shared token.
5.  Crabbox fails to properly validate the injected headers against the authenticated token.
6.  The authorization check is bypassed due to the spoofed identity headers.
7.  The attacker gains unauthorized access to the victim's owner/org-scoped lease operations.
8.  The attacker performs malicious actions, such as modifying or deleting lease information, potentially leading to data loss or service disruption.

## Impact

Successful exploitation of CVE-2026-8621 allows unauthorized access to sensitive lease operations within the Crabbox system. This can result in data breaches, data manipulation, or service disruption depending on the specific functions exposed and the scope of the lease operations. While the specific number of potential victims is unknown, any organization using Crabbox versions prior to v0.12.0 with shared token authentication enabled is at risk.

## Recommendation

*   Upgrade Crabbox to version v0.12.0 or later to patch CVE-2026-8621 (reference: <https://github.com/openclaw/crabbox/releases/tag/v0.12.0>).
*   Deploy the Sigma rule "Detect Crabbox Authentication Bypass Attempt via Spoofed Headers" to identify exploitation attempts by monitoring for the presence of `X-Crabbox-Owner` and `X-Crabbox-Org` headers in requests.
*   Review and restrict the usage of shared tokens in Crabbox to minimize the attack surface.
*   Implement input validation on the `X-Crabbox-Owner` and `X-Crabbox-Org` headers if shared tokens are required, ensuring they match the authenticated user's expected identity.
