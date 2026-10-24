---
brief_id: brief-2026-10-24-ablocks-privilege-escalation
event_id: brief-2026-10-24-ablocks-privilege-escalation
revision: 2
activity_at: "2026-10-24T15:15:31Z"
revision_history:
  - revision: 2
    at: "2026-10-24T15:15:31Z"
    checksum: sha256:6f00832ec8eefa13d19deaa877d71300fe2bd399c14cf3f65e0708bbb5c501e3
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-110018&utm_source=rss&utm_medium=rss
title: 'aBlocks: WordPress Plugin Privilege Escalation (CVE-2026-110018)'
slug: 2026-10-ablocks-privilege-escalation
description: The aBlocks WordPress plugin fails to validate user input within the /ablocks/v1/form-builder/registration REST endpoint, allowing authenticated users with Contributor access to escalate privileges to Editor.
date: "2026-10-24T14:16:08Z"
lastmod: "2026-10-24T15:14:59Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ablocks:ablocks:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-110018&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - privilege-escalation
  - web-application
vendors:
  - aBlocks
products:
  - aBlocks – Gutenberg Blocks, User Dashboard Builder, Popup Builder, Form Builder & Animation Builder (<= 2.17.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Contributor-level access and above, to escalate their WordPress role to Editor.
    confidence_band: high
cves:
  - id: CVE-2026-110018
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110018
  - https://sploitus.com/exploit?id=CVE-2026-110018&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade aBlocks plugin to the latest version to patch CVE-2026-110018.
      owner: IT Operations
      due: 24h
      evidence: Source confirms plugin is vulnerable in all versions up to and including 2.17.0.
  hunt_leads:
    - lead: Identify unauthorized account privilege elevation by monitoring WordPress user role change logs.
      technique_id: T1068
      data_needed:
        - WordPress authentication logs
        - User role change event logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit results in the application of WP_User::set_role() to elevate account privileges.
  mitigation_plan:
    - priority: immediate
      action: Update aBlocks plugin to version > 2.17.0.
      owner: IT Operations
      addresses: CVE-2026-110018
      evidence: Plugin version 2.17.0 and below are confirmed vulnerable.
updates:
  - at: "2026-10-24T15:14:59Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-110018&utm_source=rss&utm_medium=rss
---

The aBlocks - Gutenberg Blocks, User Dashboard Builder, Popup Builder, Form Builder & Animation Builder plugin for WordPress is vulnerable to a privilege escalation vulnerability (CVE-2026-110018) in versions up to and including 2.17.0. The vulnerability arises from an improperly configured REST API permission callback in the `/ablocks/v1/form-builder/registration` endpoint.

The plugin allows an attacker with Contributor-level access to manipulate the `roleSlug` attribute. By saving a block with `formType='login'` and subsequently triggering the registration endpoint, the attacker can bypass validation checks that only occur during the save process. The vulnerability is mitigated for administrator-level roles by an `is_safe_registration_role()` function that rejects roles with critical management capabilities, limiting escalation to the Editor role or lower.

## Impact
Successful exploitation allows an authenticated user with at least Contributor-level access to escalate their account privileges to Editor. This provides the attacker with elevated access to site content and administrative capabilities associated with the Editor role.

## Recommendation
- Update the "aBlocks - Gutenberg Blocks, User Dashboard Builder, Popup Builder, Form Builder & Animation Builder" plugin to a version released after 2.17.0.
- Audit existing user accounts for unexpected elevation to Editor or other high-privilege roles.
- Review WordPress REST API logs for anomalous requests to the `/ablocks/v1/form-builder/registration` endpoint, particularly from users with Contributor-level roles.
