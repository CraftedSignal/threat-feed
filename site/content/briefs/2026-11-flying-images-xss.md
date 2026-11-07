---
brief_id: brief-2026-11-07-flying-images-xss
event_id: brief-2026-11-07-flying-images-xss
revision: 1
activity_at: "2026-11-07T05:59:05Z"
title: 'Flying Images: Stored Cross-Site Scripting (CVE-2026-119175)'
slug: 2026-11-flying-images-xss
description: The Flying Images WordPress plugin version 2.4.15 and earlier contains a stored XSS vulnerability in the comment parameter, allowing unauthenticated attackers to execute arbitrary scripts after comment approval.
date: "2026-11-07T05:59:05Z"
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
  - cpe:2.3:a:flying_images:flying_images:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-application
  - wordpress
  - cve-2026-119175
vendors:
  - Flying Images
products:
  - 'Flying Images: Optimize and Lazy Load Images for Faster Page Speed (<= 2.4.15)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-119175
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119175
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Identify and update instances of Flying Images plugin to version > 2.4.15
      owner: IT Operations
      due: 48h
      evidence: The plugin is vulnerable in versions up to and including 2.4.15.
  hunt_leads:
    - lead: Hunt for JavaScript tags or event handlers (e.g., <script>, onerror, onload) within the wp_comments table
      technique_id: T1059.007
      data_needed:
        - Database records for WordPress comment content
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows stored XSS via the comment parameter.
---

The Flying Images: Optimize and Lazy Load Images for Faster Page Speed plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 2.4.15. The vulnerability arises from insufficient sanitization and escaping of the 'comment' parameter. Unauthenticated attackers can inject malicious scripts into comments. If an administrator approves the initial comment, subsequent comments from the same author credentials bypass future moderation, enabling the injected script to execute in the browsers of visitors and administrators viewing the affected page.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of users viewing the affected WordPress pages, potentially leading to session hijacking, administrative action performed on behalf of the victim, or credential theft.

## Recommendation
- Update the Flying Images: Optimize and Lazy Load Images for Faster Page Speed plugin to the latest version beyond 2.4.15 immediately.
- Implement a Web Application Firewall (WAF) to filter common XSS payloads in HTTP POST requests targeting WordPress comment endpoints.
- Audit existing comment sections for unauthorized scripts if the plugin was deployed in a public-facing configuration.
