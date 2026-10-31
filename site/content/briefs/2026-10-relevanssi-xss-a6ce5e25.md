---
brief_id: brief-2026-10-31-relevanssi-xss-a6ce5e25
event_id: brief-2026-10-31-relevanssi-xss-a6ce5e25
revision: 1
activity_at: "2026-10-31T07:52:17Z"
title: 'Relevanssi WordPress plugin: Stored Cross-Site Scripting (CVE-2026-116522)'
slug: 2026-10-relevanssi-xss-a6ce5e25
description: The Relevanssi - A Better Search plugin for WordPress (v4.28.5 and earlier) is vulnerable to stored cross-site scripting (XSS) via the comment parameter, allowing unauthenticated attackers to execute arbitrary scripts when specific search-highlighting features are enabled.
date: "2026-10-31T07:52:17Z"
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
  validation_status: Source verified
cpes:
  - cpe:2.3:a:relevanssi:relevanssi:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-application
  - cms
vendors:
  - Relevanssi
products:
  - Relevanssi – A Better Search (<= 4.28.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages.
    confidence_band: high
cves:
  - id: CVE-2026-116522
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116522
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Web Security Team
  immediate_actions:
    - action: Check Relevanssi plugin version and verify if comment indexing/highlighting features are active
      owner: IT Operations
      due: 24h
      evidence: Vulnerability requires these features enabled to be exploitable.
  hunt_leads:
    - lead: Inspect WordPress database or server access logs for anomalous comment content containing script tags or JavaScript events
      technique_id: T1059.007
      data_needed:
        - Database comment tables
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers inject arbitrary web scripts via the comment parameter.
  mitigation_plan:
    - priority: immediate
      action: Disable comment indexing and highlighting in Relevanssi settings
      owner: IT Operations
      addresses: CVE-2026-116522
      evidence: Vulnerability occurs when these options are enabled.
---

The Relevanssi - A Better Search plugin for WordPress contains a stored cross-site scripting vulnerability caused by insufficient input sanitization and output escaping. An unauthenticated attacker can inject arbitrary web scripts via the 'comment' parameter. The vulnerability only triggers when the target WordPress site has both 'comment indexing' and 'comment highlighting' options enabled, and a user visits a singular page via a search-result permalink that includes the highlight query parameter.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary scripts in the context of a user's browser session.

## Recommendation
- Update the Relevanssi - A Better Search plugin to version 4.28.6 or higher, once available.
- Disable the 'comment indexing' and 'comment highlighting' features in the Relevanssi plugin settings as a temporary mitigation if patching is not immediately feasible.
- Audit existing comment content for suspicious script tags or obfuscated JavaScript.
