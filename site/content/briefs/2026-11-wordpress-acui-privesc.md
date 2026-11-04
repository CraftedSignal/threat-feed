---
brief_id: brief-2026-11-04-wordpress-acui-privesc
event_id: brief-2026-11-04-wordpress-acui-privesc
revision: 2
activity_at: "2026-11-04T12:01:26Z"
revision_history:
  - revision: 2
    at: "2026-11-04T12:01:26Z"
    checksum: sha256:c72a6a2beb31f7c2c29bff9e1ba291eb2764687d120bb7afc7aa7ef0fa0e9301
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-120554&utm_source=rss&utm_medium=rss
title: 'Import and export users and customers: Privilege escalation in ACUI_Cron (CVE-2026-120554)'
slug: 2026-11-wordpress-acui-privesc
description: The Import and export users and customers plugin for WordPress is vulnerable to privilege escalation due to a non-atomic configuration write sequence in the ACUI_Cron::save_settings() function that fails to authorize role changes before persistence.
date: "2026-11-04T10:42:27Z"
lastmod: "2026-11-04T12:00:40Z"
type: advisory
claim_state: <nil>
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
  validation_status: Source verified; environment-specific validation required
cpes:
  - cpe:2.3:a:import_and_export_users_and_customers_project:import_and_export_users_and_customers:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-120554&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - privilege-escalation
  - cms
vendors:
  - WordPress
products:
  - Import and export users and customers (<= 2.5.11)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Import and export users and customers plugin for WordPress is vulnerable to Privilege Escalation... makes it possible for authenticated attackers holding a custom delegated role... to escalate their privileges to Administrator
    confidence_band: high
cves:
  - id: CVE-2026-120554
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120554
  - https://sploitus.com/exploit?id=CVE-2026-120554&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all WordPress instances and identify versions of the Import and export users and customers plugin.
      owner: IT Operations
      due: 24h
      evidence: Vulnerable plugin identified in NVD advisory.
  hunt_leads:
    - lead: Monitor for suspicious modifications to WordPress options or cron job settings by users with delegated roles (create_users capability).
      technique_id: T1068
      data_needed:
        - WordPress database update logs
        - WordPress plugin activity logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves manipulation of acui_cron settings in the database.
  mitigation_plan:
    - priority: immediate
      action: Update the Import and export users and customers plugin to the latest secure version once available.
      owner: IT Operations
      addresses: CVE-2026-120554
      evidence: NVD advisory for CVE-2026-120554.
updates:
  - at: "2026-11-04T12:00:40Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-120554&utm_source=rss&utm_medium=rss
---

The "Import and export users and customers" plugin for WordPress (versions up to and including 2.5.11) contains a privilege escalation vulnerability. The `ACUI_Cron::save_settings()` function improperly persists configuration options (`acui_cron_activated`, `acui_cron_configured_by`, `acui_cron_user_id`, and `acui_cron_path_to_file`) before executing authorization checks. Authenticated users with the `create_users` capability can exploit this race condition to modify administrative settings and escalate their privileges to Administrator during an unattended cron task execution.

## Impact
An authenticated attacker with limited capabilities (`create_users`) can gain full administrative access to the WordPress environment by manipulating cron settings, potentially leading to total system compromise.

## Recommendation
- Inventory WordPress installations running the "Import and export users and customers" plugin and verify the version.
- Update the plugin to the latest version (patch for 2.5.11) as soon as the vendor provides a release.
- If a patch is unavailable, disable the plugin or restrict access to administrative functions to trusted users only.
- Audit user roles and capabilities to minimize users with the `create_users` permission.
