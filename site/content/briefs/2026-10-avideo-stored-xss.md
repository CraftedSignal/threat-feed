---
title: Stored Cross-Site Scripting in WWBN AVideo via Video Titles
slug: 2026-10-avideo-stored-xss
description: WWBN AVideo versions 12.4 through 29.2.0 are vulnerable to stored cross-site scripting (XSS) due to improper sanitization of doubly-encoded HTML entities in video titles, allowing authenticated attackers to execute arbitrary scripts in the context of gallery and playlist pages.
date: "2026-10-04T16:54:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wwbn:avideo:*:*:*:*:*:*:*:*
vendors:
  - WWBN
products:
  - AVideo (12.4 through 29.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: WWBN AVideo 12.4 through 29.2.0 contains a stored cross-site scripting vulnerability that allows authenticated uploaders to inject HTML.
    confidence_band: high
cves:
  - id: CVE-2026-105086
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105086
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch WWBN AVideo to the latest version to address CVE-2026-105086.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-105086
  hunt_leads:
    - lead: Search web server logs for requests to video upload endpoints containing encoded HTML entities or script tags.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability involves injecting malicious markup via video titles.
---

WWBN AVideo, an open-source video platform, contains a stored cross-site scripting (XSS) vulnerability affecting versions 12.4 through 29.2.0 (CVE-2026-105086). The vulnerability arises from an improper input sanitization process involving the safeString() function. The application attempts to strip malicious HTML tags before decoding entities. However, due to a double-encoding flaw where entities are processed twice by the setTitle() and save() methods, an authenticated user can bypass these security checks. By submitting video titles containing doubly-encoded HTML entities, an attacker can store malicious JavaScript markup within the application database. This payload is subsequently rendered and executed when other users or administrators visit pages such as trending, gallery, embed, or playlist views. This vulnerability is significant as it allows for session hijacking, credential theft, or unauthorized actions performed on behalf of legitimate users who interact with the infected video content.

## Impact

Successful exploitation allows authenticated attackers to inject and execute arbitrary JavaScript in the browsers of other users viewing the application. Potential consequences include the compromise of user sessions, theft of sensitive cookies, or unauthorized modification of application data. The vulnerability affects a broad range of AVideo versions (12.4 to 29.2.0), potentially impacting any organization hosting this video platform for internal or external media distribution.

## Recommendation

* Update WWBN AVideo to a version beyond 29.2.0 that includes the security patch for CVE-2026-105086.
* Until patching is possible, implement strict input validation on the application's video metadata upload API to block doubly-encoded entities.
* Audit application logs for suspicious activity on the video upload and metadata management endpoints.
* Monitor for unexpected requests to the trending, gallery, or playlist pages that contain script-related characters.
