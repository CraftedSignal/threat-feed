---
brief_id: brief-2026-11-07-translatepress-xss
event_id: brief-2026-11-07-translatepress-xss
revision: 1
activity_at: "2026-11-07T05:59:44Z"
title: 'TranslatePress: Stored Cross-Site Scripting (CVE-2026-119167)'
slug: 2026-11-translatepress-xss
description: The TranslatePress WordPress plugin is vulnerable to Stored Cross-Site Scripting via insufficient sanitization of the comment parameter, allowing unauthenticated attackers to inject malicious scripts.
date: "2026-11-07T05:59:44Z"
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
  validation_status: Analysis based on NVD advisory, no environment-specific validation performed.
cpes:
  - cpe:2.3:a:translatepress:translatepress:*:*:*:*:*:wordpress:*:*
vendors:
  - TranslatePress
products:
  - TranslatePress – Translate Multilingual sites with AI Translation (<= 3.3.8)
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
    evidence: Unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-119167
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119167
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade TranslatePress plugin to version > 3.3.8
      owner: IT Operations
      due: 48h
      evidence: Vulnerable in all versions up to, and including, 3.3.8
  hunt_leads:
    - lead: Inspect WordPress comment database or audit logs for script tags or common XSS payloads in comment bodies.
      technique_id: T1059.007
      data_needed:
        - WordPress database comments table
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerable to Stored Cross-Site Scripting via the comment parameter
---

The TranslatePress - Translate Multilingual sites with AI Translation plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS). The vulnerability exists in the 'comment' parameter due to insufficient input sanitization and output escaping.

## Impact
Unauthenticated attackers can inject arbitrary web scripts into pages that execute when a user accesses the affected page. Successful exploitation requires two conditions: the attacker must have a previously approved comment under WordPress's default moderation settings, and the TranslatePress plugin must have a secondary language configured.

## Recommendation
- Upgrade the TranslatePress - Translate Multilingual sites with AI Translation plugin to a version beyond 3.3.8.
- Review WordPress comment moderation logs for suspicious activity involving previously approved accounts.
- Implement a Content Security Policy (CSP) to mitigate the impact of stored XSS attacks.
