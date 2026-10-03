---
title: Authorization Bypass in Nelio Content WordPress Plugin
slug: 2026-10-nelio-auth-bypass
description: An authorization bypass vulnerability in the Nelio Content WordPress plugin allows authenticated contributors to delete arbitrary reusable social messages.
date: "2026-10-03T08:54:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nelio:nelio_content:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - web-application
vendors:
  - Nelio
products:
  - Nelio Content – Editorial Calendar & Social Media Auto-Posting (<= 4.5.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with contributor-level access and above, to permanently delete any reusable social message.
    confidence_band: high
cves:
  - id: CVE-2026-94505
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94505
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  hunt_leads:
    - lead: Monitor WordPress audit logs for deletion actions of 'nc_reusable_social' post types initiated by users with contributor roles
      technique_id: T1068
      data_needed:
        - WordPress plugin/application logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies vulnerability allows unauthorized deletion by contributors
  mitigation_plan:
    - priority: immediate
      action: Update Nelio Content plugin to the latest available version beyond 4.5.0
      owner: IT Operations
      addresses: CVE-2026-94505
      evidence: Source states versions up to 4.5.0 are vulnerable
---

The Nelio Content - Editorial Calendar & Social Media Auto-Posting plugin for WordPress is affected by an authorization bypass vulnerability (CVE-2026-94505) in all versions up to and including 4.5.0. The vulnerability stems from the plugin's failure to adequately verify user permissions before executing deletion actions on the `nc_reusable_social` post type. 

An attacker with at least contributor-level access can leverage this flaw to permanently remove social media content authored by other users, including site administrators. This issue represents a significant integrity risk to content calendars and automated social media workflows managed via the plugin. Because the vulnerability exists within the application's authorization logic, it does not require additional software to exploit beyond standard authenticated access to the WordPress backend.

## Impact

Successful exploitation results in the unauthorized, permanent deletion of reusable social media messages across the WordPress installation. This impact primarily affects marketing operations and editorial calendars, potentially causing significant disruption to social media campaigns and loss of prepared content. The vulnerability affects all users running Nelio Content versions 4.5.0 or older.

## Recommendation

Prioritize the update of the Nelio Content plugin to the latest version. Monitor WordPress administrative access logs for unusual deletion activity associated with users assigned the 'contributor' role.
