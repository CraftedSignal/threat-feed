---
brief_id: brief-2026-10-28-affiliate-toolkit-xss
event_id: brief-2026-10-28-affiliate-toolkit-xss
revision: 1
activity_at: "2026-10-28T06:26:21Z"
title: 'affiliate-toolkit: Stored Cross-Site Scripting via atkp_product_producturl (CVE-2026-111314)'
slug: 2026-10-affiliate-toolkit-xss
description: The affiliate-toolkit WordPress plugin contains a stored XSS vulnerability in the atkp_product_producturl parameter, allowing unauthenticated or contributor-level attackers to inject arbitrary web scripts.
date: "2026-10-28T06:26:21Z"
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
  - cpe:2.3:a:affiliate-toolkit:affiliate-toolkit:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - wordpress
  - plugin
vendors:
  - affiliate-toolkit
products:
  - affiliate-toolkit – Multi-Network Affiliate & Amazon Product Display (<= 3.9.2)
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
  - id: CVE-2026-111314
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111314
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify all WordPress instances running affiliate-toolkit versions 3.9.2 or older
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects all versions up to, and including, 3.9.2
  hunt_leads:
    - lead: Inspect plugin configuration for suspicious content in atkp_product_producturl
      technique_id: T1059.007
      data_needed:
        - WordPress database entries for affiliate-toolkit plugin settings
        - Web server access logs showing POST requests to plugin AJAX endpoints
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability exists via the atkp_product_producturl parameter
  mitigation_plan:
    - priority: immediate
      action: Upgrade affiliate-toolkit to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-111314
      evidence: Vulnerability exists in all versions up to, and including, 3.9.2
---

The affiliate-toolkit - Multi-Network Affiliate & Amazon Product Display plugin for WordPress (versions 3.9.2 and earlier) is vulnerable to Stored Cross-Site Scripting (XSS). The vulnerability exists in the atkp_product_producturl parameter due to insufficient input sanitization and output escaping.

## Impact
Successful exploitation allows for the execution of arbitrary web scripts in the context of a user's browser session. When the plugin AJAX handler is enabled, unauthenticated attackers can trigger this vulnerability by providing a target product ID. In default configurations, the attack requires contributor-level privileges or higher.

## Recommendation
- Update the affiliate-toolkit WordPress plugin to the version patched beyond 3.9.2.
- Audit existing product URLs stored within the affiliate-toolkit plugin configuration for malicious script injections.
- Monitor WordPress administrative logs for unusual product creation or modification activity originating from contributor-level accounts.
