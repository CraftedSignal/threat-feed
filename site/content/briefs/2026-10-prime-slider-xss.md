---
brief_id: brief-2026-10-28-prime-slider-xss
event_id: brief-2026-10-28-prime-slider-xss
revision: 1
activity_at: "2026-10-28T08:27:32Z"
title: 'Prime Slider WordPress plugin: Stored Cross-Site Scripting (CVE-2026-111111)'
slug: 2026-10-prime-slider-xss
description: The Prime Slider plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) due to insufficient input sanitization, allowing unauthenticated attackers to inject malicious HTML attributes that execute in the context of victim browsers.
date: "2026-10-28T08:27:32Z"
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
  validation_status: Source verified; standard XSS advisory reporting
cpes:
  - cpe:2.3:a:prime_slider:prime_slider:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-application
  - cve
vendors:
  - WordPress
products:
  - Prime Slider – Hero Slider, Carousel, WooCommerce & Post Slider Elementor Addons (<= 4.7.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: promoting previously inert bytes — such as event handlers like onfocus — into real HTML attributes
    confidence_band: high
cves:
  - id: CVE-2026-111111
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111111
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Prime Slider plugin to version > 4.7.2
      owner: IT Operations
      due: 48h
      evidence: Vulnerability exists in all versions up to and including 4.7.2
  hunt_leads:
    - lead: Inspect web server access logs for POST requests to the WordPress environment containing suspicious HTML event handler strings (e.g., onfocus, onerror, onload) in the request body
      technique_id: T1190
      data_needed:
        - Web server access/error logs
        - WAF request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: regex fallback consumes closing quotes of allowed attribute values containing bdt-
  mitigation_plan:
    - priority: immediate
      action: Update WordPress plugin
      owner: IT Operations
      addresses: CVE-2026-111111
      evidence: NVD advisory for CVE-2026-111111
---

The Prime Slider - Hero Slider, Carousel, WooCommerce & Post Slider Elementor Addons plugin for WordPress (versions up to and including 4.7.2) contains a Stored Cross-Site Scripting (XSS) vulnerability. The flaw exists because the plugin utilizes a regex fallback mechanism that improperly parses input attributes, specifically by consuming the closing quotes of allowed attributes. This action promotes previously inert bytes, such as event handlers (e.g., onfocus), into active HTML attributes. These malicious payloads are stored in the database and subsequently executed when a victim views the affected page.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser session of a user viewing the injected content. This may lead to session hijacking, unauthorized actions performed on behalf of the user, or redirection to malicious sites.

## Recommendation
- Update the "Prime Slider - Hero Slider, Carousel, WooCommerce & Post Slider Elementor Addons" plugin to a version released after 4.7.2.
- Until patching is possible, restrict access to administrative interfaces and pages utilizing the plugin to authorized users only.
- Implement a Web Application Firewall (WAF) to filter incoming HTTP requests for suspicious HTML event handlers and script tags in the 'comment' parameter.
