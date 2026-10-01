---
title: CVE-2026-93882 - IDOR in LearnPress WordPress LMS Plugin
slug: 2026-10-learnpress-idor
description: An unauthenticated IDOR vulnerability in the LearnPress WordPress plugin allows unauthorized access to private course materials by manipulating the course and item identifiers in AJAX requests.
date: "2026-10-01T08:39:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:thimpress:learnpress:*:*:*:*:*:*:*:*
tags:
  - idor
  - wordpress
  - lms
  - web-application-vulnerability
vendors:
  - ThimPress
products:
  - LearnPress (<= 4.4.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The endpoint is explicitly listed in the AbstractAjax no-nonce allowlist and performs no capability check.
    confidence_band: high
cves:
  - id: CVE-2026-93882
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93882
rules:
  - title: Detects CVE-2026-93882 Exploitation - IDOR Attempt on LearnPress
    description: Detects potential exploitation of CVE-2026-93882 via suspicious POST requests to the LearnPress AJAX handler that may indicate IDOR enumeration.
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
    - Security Operations
  immediate_actions:
    - action: Upgrade LearnPress to the latest secure version beyond 4.4.8.
      owner: IT Operations
      due: 24h
      evidence: Plugin version identified as vulnerable up to 4.4.8.
  hunt_leads:
    - lead: Search logs for multiple 200 OK responses to lp-ajax-handle with varying item_id parameters from the same source IP.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker requires enumerating items via IDOR.
  mitigation_plan:
    - priority: immediate
      action: Disable the plugin if patching is delayed.
      owner: IT Operations
      addresses: CVE-2026-93882
      evidence: Vulnerability allows unauthenticated access.
---

CVE-2026-93882 describes an Insecure Direct Object Reference (IDOR) vulnerability within the LearnPress WordPress plugin, impacting versions up to and including 4.4.8. The vulnerability resides in the CourseMaterialTemplate::render_material_items() callback, which is exposed through the public 'lp-ajax-handle' endpoint. This specific endpoint is included in the plugin's no-nonce allowlist and lacks necessary capability checks.

The flaw occurs because the handler performs authorization validation based solely on an attacker-supplied 'course_id', while retrieving course-material records using an independently attacker-supplied 'item_id'. By targeting a site that has at least one course with 'No Required Enroll' enabled, an unauthenticated attacker can supply the identifier of a public course to bypass initial checks and then leverage the 'item_id' parameter to retrieve, read, or download materials associated with private, paid, or enrollment-restricted courses. This exposure poses a significant risk to the confidentiality of proprietary educational content and student-accessible materials.

## Attack Chain

1. Attacker identifies a WordPress site running LearnPress version 4.4.8 or earlier.
2. Attacker discovers the public 'lp-ajax-handle' endpoint exposed by the plugin.
3. Attacker identifies at least one course on the target site with the 'No Required Enroll' setting enabled.
4. Attacker crafts an AJAX request to the endpoint, setting the 'action' parameter to 'load_content_via_ajax'.
5. Attacker provides the 'course_id' of the public course to pass the superficial authorization check within the handler.
6. Attacker provides the 'item_id' corresponding to a private or paid resource in the target course.
7. The vulnerable 'render_material_items()' method processes the request, ignoring the ownership check between the 'course_id' and 'item_id'.
8. The server returns the sensitive file path or external URL for the requested private material to the attacker.

## Impact

Successful exploitation allows unauthenticated users to gain unauthorized access to private and paid course materials. This results in the potential leak of proprietary intellectual property, protected digital assets, and sensitive student resources. The vulnerability affects any site utilizing LearnPress for LMS functionality where sensitive materials are stored in courses that are not intended for public access.

## Recommendation

1. Upgrade the LearnPress plugin to a version patched against CVE-2026-93882 immediately.
2. Implement a Web Application Firewall (WAF) rule to inspect and block requests to the 'lp-ajax-handle' endpoint that contain suspicious 'item_id' parameters if a patch cannot be immediately deployed.
3. Review access logs for high-frequency requests to the 'lp-ajax-handle' endpoint from unauthenticated users, specifically looking for variations in the 'item_id' field.
4. Audit current LearnPress configurations to ensure that sensitive materials are not stored in courses with 'No Required Enroll' enabled until the update is applied.
