---
brief_id: brief-2026-10-29-mapster-wp-maps-xss
event_id: brief-2026-10-29-mapster-wp-maps-xss
revision: 1
activity_at: "2026-10-29T11:13:50Z"
title: 'Mapster WP Maps: Stored Cross-Site Scripting (CVE-2026-107743)'
slug: 2026-10-mapster-wp-maps-xss
description: The Mapster WP Maps plugin for WordPress up to version 2.0.5 contains a stored cross-site scripting vulnerability that allows unauthenticated attackers to inject malicious scripts into map configurations via the REST API.
date: "2026-10-29T11:13:50Z"
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
  validation_status: Source verified
cpes:
  - cpe:2.3:a:mapster:wp_maps:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-application
  - wordpress
  - cve-2026-107743
vendors:
  - Mapster
products:
  - Mapster WP Maps (<= 2.0.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can leverage an improperly secured REST API endpoint (/wp-json/mapster-wp-maps/save-mapmaker) to inject malicious scripts into map configurations.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-107743
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107743
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Mapster WP Maps to the latest version
      owner: IT Operations
      due: 48h
      evidence: Vulnerability impacts all versions up to 2.0.5
  hunt_leads:
    - lead: Identify unauthenticated POST requests to the mapmaker REST endpoint
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerable route is /wp-json/mapster-wp-maps/save-mapmaker and lacks permission callbacks
  mitigation_plan:
    - priority: immediate
      action: Apply WAF block for the vulnerable endpoint if immediate patching is not possible
      owner: SOC
      addresses: CVE-2026-107743
      evidence: The exploit leverages the unauthenticated REST API endpoint
---

The Mapster WP Maps plugin for WordPress (versions 2.0.5 and below) is vulnerable to Stored Cross-Site Scripting (XSS). An unauthenticated attacker can reach the `/wp-json/mapster-wp-maps/save-mapmaker` REST endpoint, which lacks capability checks or nonce validation. The `mapster_write_config_to_acf()` helper improperly sanitizes inputs, leaving quote characters intact. Subsequently, the `mapster_wp_map` shortcode renderer concatenates the `loading_background_color` value directly into an inline style attribute without output escaping, leading to arbitrary JavaScript execution in the browser of any user viewing an affected page.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim user's browser, potentially leading to unauthorized actions, session hijacking, or defacement of WordPress pages where the plugin is embedded.

## Recommendation

- Upgrade the Mapster WP Maps plugin to the latest version as provided by the vendor.
- Audit WordPress site logs for unauthorized POST requests to the `/wp-json/mapster-wp-maps/save-mapmaker` endpoint.
- Implement Web Application Firewall (WAF) rules to restrict access to the `/wp-json/mapster-wp-maps/` REST route if the functionality is not actively required for public-facing features.
