---
brief_id: brief-2026-10-24-user-profile-builder-privilege-escalation
event_id: brief-2026-10-24-user-profile-builder-privilege-escalation
revision: 2
activity_at: "2026-10-24T07:08:43Z"
revision_history:
  - revision: 2
    at: "2026-10-24T07:08:43Z"
    checksum: sha256:fd251f133625cbd24e88abdf9f8a9b38404e636343b8c756377d1a87a141e0a3
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115807&utm_source=rss&utm_medium=rss
title: 'User Profile Builder: Privilege Escalation via Gutenberg Register block (CVE-2026-115807)'
slug: 2026-10-user-profile-builder-privilege-escalation
description: The User Profile Builder plugin for WordPress is vulnerable to privilege escalation because it fails to authorize the role assignment attribute in the Gutenberg Register block, allowing authenticated users to register accounts with higher-privileged roles.
date: "2026-10-24T06:09:10Z"
lastmod: "2026-10-24T07:08:05Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass_with_fixes
  validation_status: Awaiting vendor patch release
cpes:
  - cpe:2.3:a:cozmoslabs:user_profile_builder:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-115807&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - privilege-escalation
  - web-application
  - cms
vendors:
  - WordPress
products:
  - User Profile Builder (<= 4.0.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The User Profile Builder – Beautiful User Registration Forms, User Profiles & User Role Editor plugin for WordPress is vulnerable to Limited Privilege Escalation in all versions up to, and including, 4.0.3.
    confidence_band: high
cves:
  - id: CVE-2026-115807
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115807
  - https://sploitus.com/exploit?id=CVE-2026-115807&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit site-wide user registration activity for suspicious patterns
      owner: SOC
      due: 24h
      evidence: Source notes that attackers can register accounts with elevated privileges
  hunt_leads:
    - lead: Search WordPress access logs for POST requests to the user registration endpoint containing role-related parameters
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The flaw is triggered by the Gutenberg Register block passing the Assigned Role attribute to the wppb-register shortcode
  mitigation_plan:
    - priority: immediate
      action: Disable the affected Gutenberg Register block or restrict page access until a patch is applied
      owner: IT Operations
      addresses: CVE-2026-115807
      evidence: Plugin vulnerable to privilege escalation in versions <= 4.0.3
updates:
  - at: "2026-10-24T07:08:05Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115807&utm_source=rss&utm_medium=rss
---

The User Profile Builder plugin for WordPress (versions up to and including 4.0.3) contains a privilege escalation vulnerability. The plugin's Gutenberg Register block handles the 'Assigned Role' attribute insecurely, passing it directly into the `[wppb-register]` shortcode without performing server-side authorization. The current implementation only restricts roles with `manage_options` or `remove_users` capabilities, leaving other high-privileged roles, such as Editor, unprotected. This allows authenticated users with Author-level access or higher to elevate their privileges by creating new accounts with these elevated roles.

## Impact
An authenticated attacker can successfully escalate their privileges by creating accounts with elevated roles (e.g., Editor). This could lead to unauthorized content modification, user management, or further exploitation of the WordPress instance.

## Recommendation
* Update the User Profile Builder plugin to the latest version once a fix is released.
* Audit WordPress user lists for unexpected account creations or unauthorized role assignments.
* Restrict access to the Gutenberg Register block to trusted users only.
* Monitor the `wp_user_registration` process for anomalies if logging is available for the `[wppb-register]` shortcode execution.
