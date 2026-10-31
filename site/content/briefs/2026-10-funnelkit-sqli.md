---
brief_id: brief-2026-10-31-funnelkit-sqli
event_id: brief-2026-10-31-funnelkit-sqli
revision: 1
activity_at: "2026-10-31T07:53:01Z"
title: 'FunnelKit Automations: Time-based SQL Injection (CVE-2026-119163)'
slug: 2026-10-funnelkit-sqli
description: The FunnelKit Automations plugin for WordPress is vulnerable to time-based SQL injection via the bwfan_cart_id parameter, allowing unauthenticated attackers to extract database information during delayed Action Scheduler job execution.
date: "2026-10-31T07:53:01Z"
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
  validation_status: Checked against NVD advisory
cpes:
  - cpe:2.3:a:funnelkit:automations:*:*:*:*:*:wordpress:*:*
vendors:
  - FunnelKit
products:
  - FunnelKit Automations (<= 3.8.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries
    confidence_band: high
cves:
  - id: CVE-2026-119163
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119163
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update FunnelKit Automations plugin to a version > 3.8.5.2
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions up to and including 3.8.5.2
  hunt_leads:
    - lead: Identify unauthenticated access to WooCommerce checkout endpoints where bwfan_cart_id contains SQL injection patterns
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves submitting a crafted bwfan_cart_id value during a guest Store API checkout
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to sanitize the bwfan_cart_id parameter
      owner: SOC
      addresses: CVE-2026-119163
      evidence: Vulnerability in bwfan_cart_id parameter due to insufficient escaping
---

The FunnelKit Automations plugin for WordPress (all versions up to and including 3.8.5.2) contains a time-based SQL injection vulnerability (CVE-2026-119163) in the 'bwfan_cart_id' parameter. Insufficient input validation and lack of prepared statements allow unauthenticated attackers to inject SQL commands.

## Attack Chain
1. Attacker identifies a public-facing WooCommerce checkout endpoint.
2. Attacker obtains a valid WooCommerce cart nonce.
3. Attacker submits a crafted 'bwfan_cart_id' parameter during a guest checkout transaction.
4. The malicious input is persisted in the site database metadata.
5. The WordPress site transitions an order status (e.g., from pending, failed, or cancelled).
6. The Action Scheduler initiates a background job that reloads the malicious metadata.
7. The SQL injection is executed within the context of the database query, causing time-based delays used for data exfiltration.

## Impact
Successful exploitation allows unauthenticated attackers to extract sensitive information from the underlying database.

## Recommendation
- Update the FunnelKit Automations plugin to the latest available version beyond 3.8.5.2 immediately.
- Audit WordPress site logs for anomalous HTTP POST requests to WooCommerce checkout endpoints containing suspicious characters or SQL keywords in the 'bwfan_cart_id' parameter.
- Implement Web Application Firewall (WAF) rules to block or sanitize input for the 'bwfan_cart_id' parameter in WooCommerce checkout traffic.
