---
title: Authorization Bypass in WP Table Builder Plugin
slug: 2026-09-wp-table-builder-auth-bypass
description: An incorrect authorization vulnerability in WP Table Builder versions <= 2.2.1 allows authenticated subscribers to trash or restore arbitrary posts via faulty permission checks.
date: "2026-09-22T08:34:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:wp_table_builder_drag_drop_table_builder:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - plugin-vulnerability
  - authorization-bypass
vendors:
  - WordPress
products:
  - WP Table Builder – Drag & Drop Table Builder (<= 2.2.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with subscriber-level access and above, to trash or restore any post, page, or custom post type on the site by supplying arbitrary post IDs.
    confidence_band: high
cves:
  - id: CVE-2026-6922
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6922
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade WP Table Builder plugin to current secure version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-6922 requires upgrade for remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade WP Table Builder plugin beyond 2.2.1
      owner: IT Operations
      addresses: CVE-2026-6922
      evidence: NVD vulnerability disclosure
---

The WP Table Builder - Drag & Drop Table Builder plugin for WordPress is affected by an incorrect authorization vulnerability (CVE-2026-6922) present in all versions up to and including 2.2.1. The flaw resides within the `trash_table_bulk()` and `restore_table_bulk()` functions. Due to an operator precedence error in the post-type validation guard, the security check fails to execute as intended. Furthermore, the permission callback associated with these functions only verifies that the user possesses a plugin-specific role, failing to perform necessary per-post-type or ownership checks. Consequently, any authenticated user - including those with low-privileged subscriber access - can provide arbitrary post IDs to trash or restore any content on the WordPress installation, including posts, pages, and custom post types. This vulnerability poses a significant risk to site integrity and availability.

## Impact

Successful exploitation allows authenticated users with minimal privileges to perform unauthorized administrative actions against site content. Attackers can mass-trash or restore posts and pages, potentially causing widespread service disruption, content loss, or unauthorized content visibility changes. This vulnerability affects any WordPress site utilizing the vulnerable version of the WP Table Builder plugin.

## Recommendation

* Upgrade the WP Table Builder - Drag & Drop Table Builder plugin to a version released after 2.2.1 immediately to resolve CVE-2026-6922.
* Review audit logs for `trash_table_bulk` or `restore_table_bulk` function calls initiated by accounts with subscriber-level permissions.
* Restrict administrative plugin access and sensitive action capabilities to high-privileged roles until the patch is applied.
