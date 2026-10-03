---
title: Authorization Bypass in Ultimate Member Plugin for WordPress
slug: 2026-10-ultimate-member-auth-bypass
description: An authorization bypass vulnerability in the Ultimate Member WordPress plugin allows unauthenticated attackers to exfiltrate private profile data via the wp_ajax_nopriv_um_get_members endpoint.
date: "2026-10-03T04:53:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ultimatemember:ultimate_member:*:*:*:*:*:wordpress:*:*
vendors:
  - Ultimate Member
products:
  - Ultimate Member – User Profile, Registration, Login, Member Directory, Content Restriction & Membership Plugin (<= 2.13.1)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This makes it possible for unauthenticated attackers to view privacy-restricted member profile field values.
    confidence_band: high
cves:
  - id: CVE-2026-93428
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93428
rules:
  - title: Detect CVE-2026-93428 Exploitation - Unauthorized Access to Member Profiles
    description: Detects exploitation attempts against the wp_ajax_nopriv_um_get_members endpoint by monitoring for requests that target the member retrieval logic.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Ultimate Member plugin to the latest available version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-93428 advisory
  hunt_leads:
    - lead: Search web logs for unauthorized access to wp_ajax_nopriv_um_get_members
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source documentation of the vulnerable endpoint
  mitigation_plan:
    - priority: immediate
      action: Patch plugin versions <= 2.13.1
      owner: IT Operations
      addresses: CVE-2026-93428
      evidence: NVD advisory
---

The Ultimate Member plugin for WordPress (versions 2.13.1 and earlier) contains a critical authorization bypass vulnerability related to the handling of user permissions. The plugin's wp_ajax_nopriv_um_get_members endpoint fails to properly verify user authorization before returning profile data. Specifically, the nonce mechanism ('um-frontend-nonce') used by this endpoint is exposed to all unauthenticated visitors through wp_localize_script. This flaw allows any anonymous user to supply the required nonce and query the endpoint to access sensitive member profile information. Attackers can leverage this to retrieve field values that were intended to be restricted to specific owners, members, or roles. This vulnerability poses a significant risk to user privacy on sites utilizing the plugin for member directories and content restriction.

## Impact

Successful exploitation allows unauthenticated attackers to exfiltrate private user profile information from WordPress installations. This can lead to the unauthorized disclosure of sensitive PII or restricted membership data, impacting any site utilizing the plugin's profile visibility features.

## Recommendation

Prioritize the update of the Ultimate Member plugin to a version addressing CVE-2026-93428. Monitor web server logs for high-frequency or unauthorized access attempts directed at the 'wp_ajax_nopriv_um_get_members' AJAX endpoint.
