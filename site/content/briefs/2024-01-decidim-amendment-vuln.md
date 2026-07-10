---
title: Decidim Amendment Acceptance Vulnerability
slug: 2024-01-decidim-amendment-vuln
description: An authentication bypass vulnerability in Decidim allows any registered user to accept or reject amendments, potentially granting them co-author status on affected proposals; versions 0.19.0 through 0.30.5 and 0.31.0.rc1 through 0.31.1 are affected.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - decidim
  - authentication-bypass
  - privilege-escalation
  - web-application
vendors:
  - Decidim
products:
  - Decidim-core
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-w5xj-99cg-rccm
  - https://github.com/decidim/decidim/blob/9d6c3d2efe5a83bb02e095824ff5998d96a75eb7/decidim-core/app/permissions/decidim/permissions.rb#L107
  - https://github.com/decidim/decidim/commit/1b99136
rules:
  - title: Decidim Suspicious Amendment Activity
    description: Detects suspicious activity related to amendment acceptance/rejection, potentially indicating exploitation of the authentication bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Decidim Amendment Rejection Attempt
    description: Detects attempts to reject amendments, which could indicate unauthorized activity.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Decidim is an open-source participatory democracy framework. A vulnerability exists within Decidim versions 0.19.0 through 0.30.5 and 0.31.0.rc1 through 0.31.1 where any authenticated user can accept or reject amendments to proposals, regardless of their authorization. This issue stems from insufficient permission checks when handling amendment reactions within the affected Decidim components. Successful exploitation allows an attacker to manipulate proposal content and gain co-author status, potentially influencing the outcome of participatory processes. There are currently no patches available; the identified workaround involves disabling amendment reactions for components using the amendable feature. This vulnerability was reported on GitHub as GHSA-w5xj-99cg-rccm.

## Attack Chain

1.  Attacker registers an account on the Decidim platform.
2.  Attacker authenticates to the Decidim platform with their registered account.
3.  Attacker identifies a proposal with the amendments feature enabled.
4.  Attacker crafts a malicious HTTP request to the `/amendments/{amendment_id}/accept` or `/amendments/{amendment_id}/reject` endpoint.
5.  The Decidim application processes the request without proper authorization checks due to the vulnerability in `decidim/permissions.rb`.
6.  The amendment is accepted or rejected based on the attacker's request.
7.  If the amendment is accepted, the attacker is granted co-author status on the proposal.
8.  Attacker leverages co-author status to influence or control the proposal.

## Impact

This vulnerability can compromise the integrity of participatory processes managed by Decidim. By exploiting the vulnerability, an attacker can manipulate proposals and gain undue influence, potentially undermining the democratic process. Impacts can range from subtle alterations of proposal content to complete control over proposal outcomes. The number of affected proposals depends on the number of Decidim installations using the vulnerable versions and having the amendment feature enabled.

## Recommendation

*   Apply the provided workaround by disabling amendment reactions for the amendable component (e.g., proposals) to mitigate the vulnerability until a patch is available (reference: Workarounds section).
*   Monitor Decidim application logs for suspicious activity related to amendment acceptance/rejection actions originating from unauthorized users. Implement a detection rule focusing on HTTP POST requests to `/amendments/{amendment_id}/accept` and `/amendments/{amendment_id}/reject` (reference: Sigma rule - Decidim Suspicious Amendment Activity).
*   Upgrade to a patched version of Decidim-core once available to remediate the vulnerability. Check the Decidim release notes for updates (reference: Affected Packages section).
