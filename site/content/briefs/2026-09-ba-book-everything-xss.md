---
title: CVE-2026-96039 Stored XSS in BA Book Everything WordPress Plugin
slug: 2026-09-ba-book-everything-xss
description: The BA Book Everything WordPress plugin contains a stored XSS vulnerability in the first_name parameter, allowing unauthenticated attackers to inject arbitrary scripts.
date: "2026-09-25T08:55:39Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - BA Book Everything (<= 1.8.27)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts.
    confidence_band: high
cves:
  - id: CVE-2026-96039
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96039
rules:
  - title: Detects CVE-2026-96039 Exploitation - Stored XSS in BA Book Everything
    description: Detects potential exploitation of CVE-2026-96039 by identifying script tags in the first_name parameter of booking form submissions.
    platform: sigma
    severity: high
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade BA Book Everything plugin to version > 1.8.27
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-96039 advisory
  hunt_leads:
    - lead: Search for <script> or JavaScript event handlers in plugin logs
      technique_id: T1190
      data_needed:
        - Web application logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Stored XSS via first_name parameter
  mitigation_plan:
    - priority: immediate
      action: Upgrade to patched version
      owner: IT Operations
      addresses: CVE-2026-96039
      evidence: Vulnerability remediation
---

The BA Book Everything plugin for WordPress, versions 1.8.27 and earlier, is vulnerable to a Stored Cross-Site Scripting (XSS) attack via the first_name parameter. The vulnerability arises from insufficient input sanitization and output escaping of data submitted through the booking process. An unauthenticated attacker can exploit this by placing a guest booking via the public [babe-booking-form] shortcode, which provides the necessary parameters (order_id, order_num, order_hash) to reach the vulnerable action_to_pay() handler. Successful exploitation allows for the execution of arbitrary JavaScript in the context of a user session when they access the affected page. This vulnerability presents a significant risk for session hijacking and unauthorized data access within WordPress environments using this plugin.

## Attack Chain

1. Attacker navigates to the public page containing the [babe-booking-form] shortcode.
2. Attacker initiates a guest booking flow, which generates a valid order_id, order_num, and order_hash.
3. Attacker submits the booking form while injecting a malicious payload into the first_name parameter.
4. The application processes the request, invoking the action_to_pay() handler.
5. The server stores the malicious JavaScript payload in the database without proper sanitization.
6. An administrative or other user visits the page where the stored booking information is rendered.
7. The user's browser executes the injected JavaScript payload, potentially leading to unauthorized actions or data exfiltration.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser of users viewing the booking information. This can result in session hijacking, administrative account compromise, and unauthorized access to sensitive booking data, impacting any WordPress site utilizing the affected version of the BA Book Everything plugin.

## Recommendation

* Update the BA Book Everything plugin to a version released after 1.8.27 to mitigate CVE-2026-96039.
* Audit access logs for high-frequency booking form submissions that include non-standard characters (like &lt;script> or alert()) in the first_name field.
* Monitor webserver access logs for POST requests to the plugin's booking handler followed by subsequent requests to the order payment or detail pages.
