---
brief_id: brief-2026-10-29-newsmanapp-xss
event_id: brief-2026-10-29-newsmanapp-xss
revision: 1
activity_at: "2026-10-29T13:18:09Z"
title: 'NewsmanApp: Stored Cross-Site Scripting via input parameters (CVE-2026-115821)'
slug: 2026-10-newsmanapp-xss
description: The NewsmanApp WordPress plugin contains a stored Cross-Site Scripting vulnerability in billing parameters that allows unauthenticated attackers to execute arbitrary scripts in the context of a user session.
date: "2026-10-29T13:18:09Z"
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
  validation_status: Source verified; standard web exploitation patterns apply.
cpes:
  - cpe:2.3:a:newsman:newsmanapp:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - wordpress
  - plugin
vendors:
  - Newsman
products:
  - NewsmanApp (<= 3.7.29)
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
    evidence: allows unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-115821
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115821
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all WordPress instances running NewsmanApp and verify plugin version
      owner: IT Operations
      due: 24h
      evidence: NewsmanApp plugin for WordPress is vulnerable... in all versions up to, and including, 3.7.29
  hunt_leads:
    - lead: Inspect web logs for POST requests containing script tags or common XSS payloads in billing parameters
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: vulnerable to Stored Cross-Site Scripting via the billing_first_name, billing_last_name parameter
  mitigation_plan:
    - priority: immediate
      action: Upgrade NewsmanApp to the latest version beyond 3.7.29
      owner: IT Operations
      addresses: CVE-2026-115821
      evidence: vulnerable... in all versions up to, and including, 3.7.29
    - priority: short_term
      action: Disable Newsman Remarketing feature
      owner: IT Operations
      addresses: CVE-2026-115821
      evidence: This vulnerability is only exploitable when the Newsman Remarketing feature is enabled
---

The NewsmanApp plugin for WordPress (versions up to and including 3.7.29) is vulnerable to stored Cross-Site Scripting (XSS). An unauthenticated attacker can exploit this via the 'billing_first_name' and 'billing_last_name' parameters. Successful exploitation requires the Newsman Remarketing feature to be enabled and a non-empty Remarketing ID to be configured. The vulnerability stems from insufficient input sanitization and output escaping.

## Impact
Successful exploitation allows for the execution of arbitrary JavaScript in the context of an affected user's browser, potentially leading to session hijacking, unauthorized actions, or information theft when an administrator or user views the compromised page.

## Recommendation
- Update the NewsmanApp plugin for WordPress to a version patched beyond 3.7.29.
- Disable the Newsman Remarketing feature as an interim mitigation if updating is not immediately possible.
- Audit WordPress web server access logs for anomalous POST requests directed at the plugin functionality, specifically those containing HTML or script tags within billing fields.
