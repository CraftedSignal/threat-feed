---
brief_id: brief-2026-11-04-getpaid-payment-bypass
event_id: brief-2026-11-04-getpaid-payment-bypass
revision: 1
activity_at: "2026-11-04T18:51:08Z"
title: 'GetPaid: Improper input validation leading to payment bypass (CVE-2026-119749)'
slug: 2026-11-getpaid-payment-bypass
description: An improper input validation vulnerability in the GetPaid WordPress plugin before 2.8.63 allows unauthenticated attackers to bypass payment requirements by submitting negative quantity values on public payment forms.
date: "2026-11-04T18:51:08Z"
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
  - cpe:2.3:a:getpaid:getpaid:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - e-commerce
  - cve
vendors:
  - GetPaid
products:
  - GetPaid (< 2.8.63)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The GetPaid plugin for WordPress before 2.8.63 contains an improper input validation vulnerability that allows unauthenticated attackers to bypass payment processing.
    confidence_band: high
cves:
  - id: CVE-2026-119749
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119749
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade GetPaid plugin to version 2.8.63 or later.
      owner: IT Operations
      due: 24h
      evidence: The GetPaid plugin for WordPress before 2.8.63 contains an improper input validation vulnerability.
  hunt_leads:
    - lead: Identify successful orders with a total value of 0.00 that contain line items with quantities.
      technique_id: T1190
      data_needed:
        - WordPress database order/invoice tables
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This allows the attacker to bypass payment gateways and trigger the process_free_payment() function, marking an invoice as paid.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to GetPaid 2.8.63.
      owner: IT Operations
      addresses: CVE-2026-119749
      evidence: CVE-2026-119749 remediation requirements
---

The GetPaid plugin for WordPress contains an improper input validation vulnerability (CVE-2026-119749) that allows unauthenticated attackers to manipulate payment processing. By supplying a negative quantity value via a public payment form, an attacker can influence the `process_item()` function to generate a negative line subtotal. This result reduces the overall invoice total to zero, which subsequently triggers the `process_free_payment()` function to mark the invoice as paid without requiring a successful payment gateway transaction.

## Impact
Successful exploitation allows for the acquisition of goods or services without actual financial compensation, leading to direct revenue loss for the affected site.

## Recommendation
- Update the GetPaid plugin to version 2.8.63 or later immediately to resolve the input validation issue.
- Review transaction logs for invoice records where the final total is zero but associated order items represent significant value.
