---
brief_id: brief-2026-10-27-tinymce-xss
event_id: brief-2026-10-27-tinymce-xss
revision: 1
activity_at: "2026-10-27T23:58:28Z"
title: 'TinyMCE: Stored cross-site scripting in media plugin (CVE-2026-116675)'
slug: 2026-10-tinymce-xss
description: TinyMCE is vulnerable to stored Cross-Site Scripting (XSS) via the media plugin, allowing attackers to inject malicious scripts through the data-mce-object attribute before sanitization occurs.
date: "2026-10-27T23:58:28Z"
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
  validation_status: Patch versions confirmed via source advisory
cpes:
  - cpe:2.3:a:tiny_technologies:tinymce:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
vendors:
  - Tiny Technologies
products:
  - TinyMCE (>= 8.5.1, < 8.9.3)
  - TinyMCE (7.9.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Attackers can inject malicious scripts via elements crafted through the data-mce-object attribute, which are created and executed before sanitization.
    confidence_band: high
cves:
  - id: CVE-2026-116675
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-mf2p-h6hf-fcwm
action_plan:
  priority: elevated
  owners:
    - IT Operations
  hunt_leads:
    - lead: Inspect application database for data-mce-object attributes containing anomalous script tags or event handlers
      technique_id: T1189
      data_needed:
        - Application database content
        - Web application logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can inject malicious scripts via elements crafted through the data-mce-object attribute
  mitigation_plan:
    - priority: immediate
      action: Upgrade TinyMCE instances to 8.9.3 or 7.9.4
      owner: IT Operations
      addresses: CVE-2026-116675
      evidence: This vulnerability has been patched in TinyMCE 8.9.3 and TinyMCE 7.9.4
---

TinyMCE versions 8.5.1 up to 8.9.2 and 7.9.3 are vulnerable to a stored XSS vulnerability within the media plugin. An attacker can craft inputs using the 'data-mce-object' attribute that the editor fails to sanitize before execution, leading to potential script execution in the context of the user's session.

## Impact
Successful exploitation results in stored Cross-Site Scripting. This allows attackers to execute arbitrary JavaScript in the browser of any user who views the affected content within the TinyMCE editor.

## Recommendation
- Upgrade TinyMCE to version 8.9.3 or higher.
- Upgrade TinyMCE to version 7.9.4 or higher.
- Audit existing content stored via the media plugin if the application is highly targeted.
