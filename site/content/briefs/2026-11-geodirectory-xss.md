---
brief_id: brief-2026-11-07-geodirectory-xss
event_id: brief-2026-11-07-geodirectory-xss
revision: 1
activity_at: "2026-11-07T03:46:27Z"
title: 'GeoDirectory: Stored Cross-Site Scripting (CVE-2026-120082)'
slug: 2026-11-geodirectory-xss
description: The GeoDirectory WordPress plugin is vulnerable to stored Cross-Site Scripting (XSS) via the post_content parameter, allowing unauthenticated attackers to execute arbitrary web scripts by bypassing shortcode sanitization filters.
date: "2026-11-07T03:46:27Z"
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
  - cpe:2.3:a:geodirectory:geodirectory:*:*:*:*:*:wordpress:*:*
vendors:
  - GeoDirectory
products:
  - GeoDirectory – WP Business Directory Plugin and Classified Listings Directory (<= 2.8.200)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: Nested shortcode payload ... makes it possible ... to inject arbitrary web scripts in pages that will execute.
    confidence_band: high
cves:
  - id: CVE-2026-120082
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120082
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update GeoDirectory plugin to a version released after 2.8.200.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions up to and including 2.8.200.
  hunt_leads:
    - lead: Inspect WordPress database and access logs for injected shortcode payloads containing nested brackets.
      technique_id: T1190
      data_needed:
        - WordPress database wp_posts table
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The nested shortcode payload ([gd_dynamic_conten[gd_tags]t ...]) defeats the plugin guard.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches or update to version 2.8.201 or higher.
      owner: IT Operations
      addresses: CVE-2026-120082
      evidence: Vulnerability exists in all versions up to and including 2.8.200.
---

The GeoDirectory WordPress plugin (up to and including version 2.8.200) contains a stored Cross-Site Scripting (XSS) vulnerability. The flaw exists because the plugin fails to sufficiently sanitize input or escape output in the 'post_content' parameter. An unauthenticated attacker can exploit this by crafting a nested shortcode payload, such as `[gd_dynamic_conten[gd_tags]t ...]`, which causes the plugin's `geodir_strip_shortcodes()` function to fail. Because WordPress's built-in `strip_shortcodes()` processes tags in a single pass, and `wp_kses_post()` focuses on HTML tags rather than shortcode attributes, malicious HTML-entity-encoded payloads are rendered and executed in the context of users viewing the injected page.

## Impact
Successful exploitation allows unauthenticated attackers to inject and execute arbitrary web scripts (XSS) within the browser of any user who accesses an affected page. This could lead to session hijacking, unauthorized actions performed on behalf of the user, or unauthorized content modification.

## Recommendation
- Update the GeoDirectory WordPress plugin to the latest available version beyond 2.8.200.
- Until patched, disable the ability for untrusted users to submit or edit posts containing shortcodes.
- Audit WordPress site logs for suspicious HTTP POST requests targeting content submission endpoints containing unusual shortcode structures or nested brackets.
