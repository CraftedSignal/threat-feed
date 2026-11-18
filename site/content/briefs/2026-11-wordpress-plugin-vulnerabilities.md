---
brief_id: brief-2026-11-18-wordpress-plugin-vulnerabilities
event_id: brief-2026-11-18-wordpress-plugin-vulnerabilities
revision: 1
activity_at: "2026-11-18T12:47:55Z"
title: 'WordPress Plugins: Multiple vulnerabilities identified by ARK WP Scanner'
slug: 2026-11-wordpress-plugin-vulnerabilities
description: Three vulnerabilities, including authentication bypass, CSRF, and resource exhaustion, were identified and patched in the WordPress plugins ElementsKit Elementor Addons, Aruba HiSpeed Cache, and Conditional Fields for Contact Form 7.
date: "2026-11-18T12:47:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE Program data.
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=8DF7AD98-4929-55F2-A358-59E133654FB7&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - vulnerability
  - webserver
  - rce
vendors:
  - Aruba.it
  - Jules Colle
  - Roxnor
products:
  - Aruba HiSpeed Cache
  - Conditional Fields for Contact Form 7
product_versions:
  - product: Aruba HiSpeed Cache
    range: < 3.0.5
  - product: Conditional Fields for Contact Form 7
    range: < 2.7.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated REST endpoint... accepted client-supplied Mailchimp credentials, letting any visitor use the site as an open proxy.
    confidence_band: high
cves:
  - id: CVE-2026-23693
    kev_status: unknown
  - id: CVE-2026-23694
    epss: 0.00254
    kev_status: "false"
  - id: CVE-2026-25863
    cvss: 7.5
    epss: 0.00451
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-23693
  - https://cveawg.mitre.org/api/cve/CVE-2026-23694
  - https://cveawg.mitre.org/api/cve/CVE-2026-25863
  - https://www.vulncheck.com/advisories/elementskit-lite-unauthenticated-mailchimp-rest-endpoint
  - https://www.vulncheck.com/advisories/conditional-fields-for-contact-form-7-dos-via-uncontrolled-resource-consumption
  - https://sploitus.com/exploit?id=8DF7AD98-4929-55F2-A358-59E133654FB7&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade ElementsKit Elementor Addons to version 3.7.9 or later.
      owner: IT Operations
      due: 24h
      evidence: Fixed in 3.7.9
    - action: Upgrade Aruba HiSpeed Cache to version 3.0.5 or later.
      owner: IT Operations
      due: 24h
      evidence: Fixed in 3.0.5
    - action: Upgrade Conditional Fields for Contact Form 7 to version 2.7.3 or later.
      owner: IT Operations
      due: 24h
      evidence: Fixed in 2.7.3
  hunt_leads:
    - lead: Identify suspicious HTTP requests directed at the WordPress REST API path '/wp-json/elementskit/v1/widget/mailchimp/subscribe'. Look for high volumes of POST requests from single or distributed IP addresses that contain Mailchimp API credentials in the request body, which indicates exploitation of the open proxy vulnerability.
      technique_id: T1190
      data_needed:
        - web_server_access_logs
        - web_application_firewall_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An unauthenticated REST endpoint (/wp-json/elementskit/v1/widget/mailchimp/subscribe) accepted client-supplied Mailchimp credentials, letting any visitor use the site as an open proxy to Mailchimp.
  mitigation_plan:
    - priority: immediate
      action: Patch all affected WordPress plugins.
      owner: IT Operations
      addresses: CVE-2026-23693, CVE-2026-23694, CVE-2026-25863
      evidence: Source identifies these as fixed versions.
---

## Overview

Research by Rahul Karne using the ARK WP Scanner tool led to the identification and coordinated disclosure of three vulnerabilities in popular WordPress plugins. Each vulnerability has been addressed by the respective vendors in updated releases. Users are advised to verify their installations against the affected version ranges and update immediately.

## Vulnerability Details

* **CVE-2026-23693 (ElementsKit Elementor Addons):** An unauthenticated REST endpoint (/wp-json/elementskit/v1/widget/mailchimp/subscribe) fails to validate Mailchimp API credentials, allowing attackers to use the WordPress site as an open proxy to Mailchimp to manipulate data or exhaust API quotas.
* **CVE-2026-23694 (Aruba HiSpeed Cache):** A cross-site request forgery (CSRF) vulnerability exists in administrative AJAX actions (ahsc_reset_options, ahsc_debug_status, ahsc_enable_purge) due to missing nonce validation. Attackers can induce administrators to perform unauthorized configuration changes.
* **CVE-2026-25863 (Conditional Fields for Contact Form 7):** An uncontrolled resource consumption vulnerability in the Wpcf7cfMailParser class allows unauthenticated attackers to submit a POST request with an unbounded iteration count, leading to memory exhaustion and a potential denial-of-service (DoS) condition.

## Recommendation

* **Patch Management:** Update all instances of the following plugins to the specified safe versions:
 * ElementsKit Elementor Addons to 3.7.9 or later.
 * Aruba HiSpeed Cache to 3.0.5 or later.
 * Conditional Fields for Contact Form 7 to 2.7.3 or later.
* **Access Control:** Regularly audit REST API endpoints and AJAX handler accessibility for unauthorized authentication requirements, particularly for plugins managing external API integrations.
