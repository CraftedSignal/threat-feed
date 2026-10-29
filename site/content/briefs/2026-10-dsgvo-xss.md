---
brief_id: brief-2026-10-29-dsgvo-xss
event_id: brief-2026-10-29-dsgvo-xss
revision: 1
activity_at: "2026-10-29T05:03:56Z"
title: 'DSGVO All in one for WP: Stored Cross-Site Scripting (CVE-2026-96741)'
slug: 2026-10-dsgvo-xss
description: The DSGVO All in one for WP plugin for WordPress is vulnerable to stored cross-site scripting (XSS) due to improper sanitization of comment content when specific integration settings are enabled.
date: "2026-10-29T05:03:56Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:dsgvo_all_in_one_for_wp_project:dsgvo_all_in_one_for_wp:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
  - cve-2026-96741
vendors:
  - DSGVO All in one for WP
products:
  - DSGVO All in one for WP (<= 5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The DSGVO All in one for WP plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96741
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96741
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Disable the Google Tag Manager integration and Replace integration automatically (Beta) features in the DSGVO All in one for WP plugin settings.
      owner: IT Operations
      due: 24h
      evidence: This is only exploitable when the administrator has enabled both the Google Tag Manager integration and the Replace integration automatically [Beta] option.
  hunt_leads:
    - lead: Hunt for suspicious comment submissions containing script tags or event handlers in WordPress comment databases.
      technique_id: T1059.007
      data_needed:
        - WordPress wp_comments table
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The plugin is vulnerable to Stored Cross-Site Scripting via Comment Content.
  mitigation_plan:
    - priority: immediate
      action: Update DSGVO All in one for WP to a version beyond 5.0 once available.
      owner: IT Operations
      addresses: CVE-2026-96741
      evidence: Vulnerable in all versions up to, and including, 5.0.
---

The DSGVO All in one for WP plugin for WordPress (versions 5.0 and earlier) contains a stored cross-site scripting (XSS) vulnerability. The flaw arises from insufficient input sanitization and output escaping when processing comment content. Exploitation is contingent upon an administrator enabling the 'Google Tag Manager' integration and the 'Replace integration automatically [Beta]' setting. Furthermore, the malicious payload must be submitted via a comment and subsequently approved by a site administrator. Successful exploitation allows for the execution of arbitrary scripts within the context of a user's browser when they access the affected page.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser of any user viewing the page containing the injected comment. This could lead to session hijacking, unauthorized actions performed on behalf of the user, or further client-side exploitation.

## Recommendation

* Update the 'DSGVO All in one for WP' plugin to a version addressing the vulnerability (when released).
* As a temporary mitigation, disable the 'Google Tag Manager' integration and the 'Replace integration automatically [Beta]' option within the plugin settings to remove the exploitation vector.
* Implement strict comment moderation policies to prevent unapproved or suspicious content from being rendered on the site.
