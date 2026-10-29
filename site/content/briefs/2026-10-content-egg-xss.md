---
brief_id: brief-2026-10-29-content-egg-xss
event_id: brief-2026-10-29-content-egg-xss
revision: 1
activity_at: "2026-10-29T21:24:45Z"
title: 'Content Egg: Stored Cross-Site Scripting via Import Queue (CVE-2026-92424)'
slug: 2026-10-content-egg-xss
description: The Content Egg plugin for WordPress contains a stored XSS vulnerability (CVE-2026-92424) allowing contributor-level users to inject malicious scripts into posts by impersonating an administrator during the import process.
date: "2026-10-29T21:24:45Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against WPScan advisory
cpes:
  - cpe:2.3:a:content_egg:content_egg:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - cve-2026-92424
vendors:
  - WordPress
products:
  - Content Egg (< 11.9.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The plugin switches to the preset author's identity before creating the resulting post, allowing users with contributor-level access and above to store arbitrary web scripts unfiltered under a privileged user's account.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A contributor-level user can trigger the bulk content-import feature and supply arbitrary scripts.
    confidence_band: high
cves:
  - id: CVE-2026-92424
    cvss: 6.8
    epss: 0.00229
    kev_status: "false"
references:
  - https://wpscan.com/vulnerability/917b8042-b38c-4b6a-9237-1dd08ada157d/
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-92424
  - https://sploitus.com/exploit?id=58C9C9E0-5B48-5915-B7FA-72D602505548&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Content Egg plugin to 11.9.0
      owner: IT Operations
      due: 24h
      evidence: Remediation section of the source advisory
  hunt_leads:
    - lead: Search WordPress access logs for POST requests to /wp-admin/admin-ajax.php with action=cegg_import_enqueue
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of the exploit trigger path via admin-ajax.php
    - lead: Identify drafts or posts containing <script> tags or suspicious attributes authored by administrators
      technique_id: T1059
      data_needed:
        - WordPress database (wp_posts table)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source describes payload execution via script tags in post content
  mitigation_plan:
    - priority: immediate
      action: Upgrade Content Egg to 11.9.0
      owner: IT Operations
      addresses: CVE-2026-92424
      evidence: Remediation section
---

CVE-2026-92424 is a stored Cross-Site Scripting (XSS) vulnerability affecting the Content Egg plugin for WordPress. The flaw originates from improper authorization and privilege escalation in the bulk content-import feature. When a user with contributor-level access invokes the import queue, the plugin insecurely impersonates the author of an import preset (typically an administrator) using `wp_set_current_user()`. This causes the post insertion process to run with the privileges of the impersonated administrator, allowing the storage of unfiltered HTML payloads.

## Attack Chain

1. The contributor harvests the `cegg_import` nonce from their own `post-new.php` UI.
2. The contributor submits a `POST` request to `wp-admin/admin-ajax.php` with the action `cegg_import_enqueue`.
3. The request specifies a `preset_id` (created by an administrator) and a malicious JSON payload containing script tags in the title or description.
4. The `ImportQueueApi::handle_enqueue()` function validates access as `edit_posts`, which the contributor possesses.
5. The background worker (`ProductImportService.php`) loads the selected preset.
6. The system executes `wp_set_current_user()` to switch identity to the preset author (the administrator).
7. The `wp_insert_post()` function is called, and because the user context is now an administrator, the `unfiltered_html` capability allows the script tag to be stored raw.
8. The script executes in the context of any administrator or editor who previews the draft, or in the browser of any visitor if the post is published.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript in the context of privileged users, enabling session hijacking, CSRF nonce exfiltration, account takeover, or site-wide defacement. The attack is misattributed to the impersonated administrator, complicating incident response.

## Recommendation

1. Upgrade the Content Egg plugin to version 11.9.0 or later immediately.
2. Audit existing Import Presets for unauthorized modifications or suspicious content.
3. Audit high-privileged user accounts for unauthorized posts or drafts created via the Content Egg plugin.
