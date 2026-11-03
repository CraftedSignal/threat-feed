---
brief_id: brief-2026-11-03-traq-xss
event_id: brief-2026-11-03-traq-xss
revision: 1
activity_at: "2026-11-03T20:04:38Z"
title: 'traQ: Stored cross-site scripting via file upload (CVE-2026-63197)'
slug: 2026-11-traq-xss
description: The traQ messenger application prior to version 3.28.3 is vulnerable to stored cross-site scripting (XSS) when configured with TRAQ_STORAGE_TYPE=local, allowing attackers to upload crafted SVG or HTML files for unauthorized JavaScript execution in a victim's browser.
date: "2026-11-03T20:04:38Z"
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
  validation_status: Source verified; patch version 3.28.3 confirmed.
cpes:
  - cpe:2.3:a:trap:traq:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - cve-2026-63197
vendors:
  - traP
products:
  - traQ (< 3.28.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker with file-upload capability can provide crafted active content and induce another user to open its file URL, causing attacker-controlled JavaScript to execute in the victim's browser.
    confidence_band: high
cves:
  - id: CVE-2026-63197
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63197
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade traQ instances to version 3.28.3
      owner: IT Operations
      due: 24h
      evidence: This issue is fixed in version 3.28.3.
  hunt_leads:
    - lead: Identify file upload activity for SVG/HTML types followed by high-frequency access to /files/ endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application upload logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An attacker with file-upload capability can provide crafted active content and induce another user to open its file URL.
  mitigation_plan:
    - priority: immediate
      action: Implement strict CSP headers to block inline script execution
      owner: IT Operations
      addresses: CVE-2026-63197
      evidence: This issue occurs when user-uploaded SVG or HTML content is rendered directly by the browser.
---

traQ messenger application versions prior to 3.28.3 contain a vulnerability when configured with `TRAQ_STORAGE_TYPE=local`. The `/files/{fileId}` retrieval endpoint returns user-uploaded SVG or HTML content without adequate security headers or sanitization, causing browsers to render the files directly. An attacker with file-upload privileges can upload malicious files containing JavaScript to trigger XSS in the context of other users who view the file.

## Impact
Successful exploitation allows an attacker to execute arbitrary JavaScript in the victim's browser session. This can lead to session hijacking, unauthorized actions performed on behalf of the user, or theft of sensitive information stored within the traQ application session.

## Recommendation
- Upgrade traQ to version 3.28.3 or later immediately.
- For instances where immediate patching is not possible, disable local file storage by modifying the `TRAQ_STORAGE_TYPE` configuration if feasible, or implement strict Content Security Policy (CSP) headers on the web server hosting the traQ application to restrict the execution of inline scripts and unauthorized sources.
- Audit logs for the `/files/{fileId}` endpoint to identify unusual access patterns or requests for files with SVG/HTML extensions from suspicious user agents.
