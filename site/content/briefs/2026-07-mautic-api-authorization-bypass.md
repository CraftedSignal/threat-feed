---
title: Mautic 7 API v2 Authorization Bypass (CVE-2026-9808)
slug: 2026-07-mautic-api-authorization-bypass
description: An authorization bypass vulnerability (CVE-2026-9808) exists in Mautic 7 API v2 endpoints, where owner-scope restrictions are not properly enforced, allowing low-privilege authenticated API users to access or modify resources belonging to other users, bypassing ownership controls and impacting data confidentiality and integrity.
date: "2026-07-03T11:33:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mautic
  - authorization-bypass
  - api
  - web-application
vendors:
  - Mautic
products:
  - Mautic Core (>= 7.0.0, < 7.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: low-privilege authenticated API users
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1220
    technique_name: Exploit Public-Facing Application
    evidence: An authorization bypass vulnerability exists in the Mautic 7 API v2 endpoints (utilizing API Platform).
    confidence_band: high
cves:
  - id: CVE-2026-9808
    cvss: 7.1
    epss: 0.00201
references:
  - https://github.com/advisories/GHSA-2jrw-c95w-h43g
---

An authorization bypass vulnerability, identified as CVE-2026-9808, has been discovered in Mautic Core versions 7.0.0 through 7.1.1. This flaw affects the API v2 endpoints, which utilize API Platform, and prevents the proper enforcement of owner-scope restrictions such as `viewown` or `editown`. Attackers, who are low-privilege authenticated API users, can leverage this vulnerability to gain unauthorized access to or modify resources belonging to other users. This bypasses the intended ownership-logic controls and structural tenant and privilege boundaries within the Mautic platform, potentially leading to data exposure or manipulation. This issue was publicly disclosed on July 2, 2026, and poses a significant risk to organizations managing sensitive marketing data through affected Mautic instances.

## Attack Chain

1.  Attacker obtains valid, low-privilege API credentials for a Mautic 7 instance (e.g., through credential compromise or an insider threat).
2.  Attacker authenticates to the Mautic API v2 endpoint using these credentials.
3.  Attacker crafts an API request targeting a resource (e.g., a specific contact, company, or report ID) that belongs to a different user or tenant.
4.  The crafted API request is sent to an affected Mautic API v2 endpoint, leveraging the vulnerability where owner-scope restrictions are not properly enforced.
5.  Mautic's API Platform processing component fails to apply the `viewown` or `editown` authorization checks for the requested resource.
6.  The Mautic application grants the attacker unauthorized read or write access to the targeted resource.
7.  Attacker successfully retrieves sensitive data or manipulates records they should not have access to, bypassing the intended security controls.

## Impact

Authenticated API users with limited roles can exploit CVE-2026-9808 to read or modify restricted resources, such as reports, contacts, and companies, that they do not own and should not have access to. This directly bypasses structural tenant and privilege boundaries on the platform, leading to unauthorized data exposure, data tampering, and potential reputational damage for affected organizations. While the number of victims is not specified, any organization utilizing Mautic Core versions 7.0.0 through 7.1.1 is vulnerable to this critical authorization flaw, particularly those with multi-tenant deployments or strict internal access controls.

## Recommendation

*   Patch CVE-2026-9808 immediately by upgrading Mautic Core to version 7.1.2 or later.
*   Temporarily revoke API credentials or narrow access permissions for any users whose roles rely on owner-scope permission containment, if immediate patching of CVE-2026-9808 is not feasible.
