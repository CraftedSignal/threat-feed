---
brief_id: brief-2026-11-04-mobile-builder-wp-priv-esc
event_id: brief-2026-11-04-mobile-builder-wp-priv-esc
revision: 1
activity_at: "2026-11-04T12:42:11Z"
title: 'Mobile builder for WordPress: Privilege escalation (CVE-2026-104799)'
slug: 2026-11-mobile-builder-wp-priv-esc
description: An authenticated privilege escalation vulnerability in the Mobile builder WordPress plugin allows attackers to overwrite account metadata, including wp_capabilities, via a faulty REST API permission check and meta-key validation logic.
date: "2026-11-04T12:42:11Z"
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
  verdict: pass
  validation_status: Source documentation confirmed; vulnerability scope defined.
cpes:
  - cpe:2.3:a:mobile_builder_project:mobile_builder:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - cms-security
products:
  - Mobile builder (<= 1.4.2)
cves:
  - id: CVE-2026-104799
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104799
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Mobile builder plugin to the version containing the fix for CVE-2026-104799
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-104799 vulnerability in Mobile builder <= 1.4.2
  hunt_leads:
    - lead: Search WordPress access logs for POST requests to /mobile-builder/v1/wcfm-profile-settings
      technique_id: T1068
      data_needed:
        - Web server access logs (Apache/Nginx/IIS)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The flaw resides in the wcfmmp_profile_settings() REST handler exposed at POST /mobile-builder/v1/wcfm-profile-settings.
  mitigation_plan:
    - priority: immediate
      action: Disable Mobile builder plugin if unable to update
      owner: IT Operations
      addresses: CVE-2026-104799
      evidence: The Mobile builder plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 1.4.2
---

The Mobile builder plugin for WordPress, in versions 1.4.2 and earlier, contains a privilege escalation vulnerability (CVE-2026-104799). The flaw resides in the `wcfmmp_profile_settings()` REST handler exposed via the `POST /mobile-builder/v1/wcfm-profile-settings` endpoint. 

The vulnerability is caused by a PHP loose-comparison error (`strpos( $key, 'mobile_builder' ) == 0`) which erroneously permits any meta key that does not contain the string 'mobile_builder'. Combined with a `permission_callback` that only checks for the existence of an authenticated user, this allows any registered user (Subscriber or higher) to update their own user metadata. Attackers can leverage this to overwrite the `wp_capabilities` field to elevate their privileges to Administrator.

## Impact

Successful exploitation allows an authenticated user to gain full administrative access to the WordPress instance, potentially leading to full site compromise.

## Recommendation

- Update the Mobile builder plugin to the latest version immediately (patching CVE-2026-104799).
- If a patch is not immediately available, disable the plugin to mitigate the risk of privilege escalation.
- Review user accounts for unexpected Administrator roles or unauthorized changes to user metadata.
