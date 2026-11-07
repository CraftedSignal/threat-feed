---
brief_id: brief-2026-11-07-wp-social-csrf
event_id: brief-2026-11-07-wp-social-csrf
revision: 1
activity_at: "2026-11-07T15:18:09Z"
title: 'Wpmet Wp Social: Cross-Site Request Forgery (CVE-2026-122675)'
slug: 2026-11-wp-social-csrf
description: The Wp Social WordPress plugin is vulnerable to CSRF via the Admin_Settings::content_xs_providers() function, allowing an attacker to overwrite social login provider credentials if an authenticated administrator visits a malicious page.
date: "2026-11-07T15:18:09Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:wpmet:wp_social:*:*:*:*:*:wordpress:*:*
vendors:
  - Wpmet
products:
  - Wp Social (<= 3.2.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Wp Social plugin for WordPress saves its social login provider settings in Admin_Settings::content_xs_providers() on the presence of the xs_provider_submit_form POST key alone.
    confidence_band: high
cves:
  - id: CVE-2026-122675
    cvss: 5.4
    kev_status: "false"
references:
  - https://patchstack.com/database/wordpress/plugin/wp-social/vulnerability/wordpress-wp-social-plugin-3-2-3-cross-site-request-forgery-csrf-vulnerability
  - https://mor-golan.github.io/research/cve-2026-122675-wp-social
  - https://vulners.com/cve/CVE-2026-122675
  - https://sploitus.com/exploit?id=016F1D22-D22F-5EB3-AF9D-1483173ACE7F&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Potential CVE-2026-122675 Exploitation
    description: Detects unauthorized POST requests to the Wp Social plugin settings endpoint which lacks CSRF protection
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Wp Social plugin to version 3.2.4 or later
      owner: IT Operations
      due: 24h
      evidence: Official fix provided in 3.2.4
  hunt_leads:
    - lead: Inspect database for abnormal social login provider configurations
      technique_id: T1098
      data_needed:
        - WordPress database options table
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Plugin overwrites xs_provider_data option
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 3.2.4
      owner: IT Operations
      addresses: CVE-2026-122675
      evidence: Patchstack vulnerability advisory
---

The Wp Social plugin for WordPress contains a Cross-Site Request Forgery (CSRF) vulnerability (CVE-2026-122675). The vulnerability exists within the `Admin_Settings::content_xs_providers()` function in `inc/admin-settings.php`. The plugin fails to perform a nonce or referer check when processing the `xs_provider_submit_form` POST request. This flaw allows an unauthenticated attacker to manipulate social login provider settings, specifically the OAuth client ID and client secret, if an administrator with an active session is lured to a malicious page.

## Impact

Successful exploitation allows an attacker to overwrite site-wide social login provider settings. This can lead to the redirection of OAuth authentication flows to attacker-controlled services, potentially facilitating unauthorized access or account takeover scenarios for users authenticating via social login providers.

## Recommendation

- Upgrade the Wp Social plugin to version 3.2.4 or later immediately.
- Audit the `xs_provider_data` option in the WordPress database for unauthorized changes to OAuth client credentials.
- Advise administrative users to avoid browsing untrusted websites while authenticated to the WordPress dashboard.
