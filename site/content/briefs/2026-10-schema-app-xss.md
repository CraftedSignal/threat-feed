---
brief_id: brief-2026-10-29-schema-app-xss
event_id: brief-2026-10-29-schema-app-xss
revision: 1
activity_at: "2026-10-29T07:09:15Z"
title: 'Schema App Structured Data: Stored Cross-Site Scripting (CVE-2026-96666)'
slug: 2026-10-schema-app-xss
description: The Schema App Structured Data plugin for WordPress through version 2.3.2 is vulnerable to stored cross-site scripting due to insufficient sanitization of comment content when the 'Remove Microdata' feature is active.
date: "2026-10-29T07:09:15Z"
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
  validation_status: Source confirmed; no Sigma possible due to lack of specific payload/request pattern data.
cpes:
  - cpe:2.3:a:schemaapp:schema_app_structured_data:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-application
vendors:
  - Schema App
products:
  - Schema App Structured Data (<= 2.3.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96666
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96666
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Disable 'Remove Microdata' option in Schema App Structured Data plugin settings.
      owner: IT Operations
      due: 24h
      evidence: Exploitation requires that an administrator has enabled the plugin's 'Remove Microdata' option.
  hunt_leads:
    - lead: Search WordPress comments for script tags or common XSS patterns.
      technique_id: T1190
      data_needed:
        - WordPress wp_comments table or administrative comment moderation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The flaw exists in the 'Remove Microdata' output filter, which fails to properly sanitize or escape input from comment content.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or disable plugin until security patch is released by vendor.
      owner: IT Operations
      addresses: CVE-2026-96666
      evidence: Vulnerability affects all versions up to, and including, 2.3.2.
---

The Schema App Structured Data plugin for WordPress contains a stored cross-site scripting (XSS) vulnerability via the 'Remove Microdata' output filter. The vulnerability affects all versions up to and including 2.3.2. Insufficient input sanitization and output escaping allow unauthenticated attackers to inject arbitrary web scripts into comment fields.

## Impact

Successful exploitation results in arbitrary script execution in the context of any user, including administrators, who views an affected page where the malicious comment has been approved.

## Recommendation

- Identify all WordPress instances running the Schema App Structured Data plugin.
- Disable the 'Remove Microdata' feature until the plugin is updated to a patched version.
- Review existing comment sections for anomalous script tags or obfuscated JavaScript, particularly in pending approval queues.
- Prioritize monitoring for administrative account actions occurring shortly after the approval of new user comments.
