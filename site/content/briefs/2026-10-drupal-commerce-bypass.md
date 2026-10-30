---
brief_id: brief-2026-10-30-drupal-commerce-bypass
event_id: brief-2026-10-30-drupal-commerce-bypass
revision: 2
activity_at: "2026-10-30T21:33:35Z"
revision_history:
  - revision: 2
    at: "2026-10-30T21:33:35Z"
    checksum: sha256:388ee12cebeb6ce8aa2b595f503169886fbeb291117fc2d9629cb5e2a7256d4b
    summary: exploited:true
    changed_fields:
      - claim_state
      - exploitation_evidence
      - lastmod
      - references
      - updates
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/drupal-security-advisory-av26-1105
title: 'Drupal Commerce Core: Access Bypass Vulnerability (CVE-2026-118539)'
slug: 2026-10-drupal-commerce-bypass
description: An unauthenticated access bypass vulnerability in the Drupal Commerce Core module is being actively exploited in the wild, leading to potential financial impact on affected e-commerce platforms.
date: "2026-10-30T11:41:41Z"
lastmod: "2026-10-30T21:33:03Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://cyber.gc.ca/en/alerts-advisories/drupal-security-advisory-av26-1105
  observed_at: "2026-10-30T15:43:17Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment-level verification of order anomalies.
cpes:
  - cpe:2.3:a:drupal:commerce:*:*:*:*:*:drupal:*:*
tags:
  - web-application-vulnerability
  - access-bypass
  - e-commerce
  - active-exploitation
vendors:
  - Drupal
products:
  - Commerce Core (versions before 3.3.13)
  - Commerce Core (versions before 8.x-2.41)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The module doesn’t sufficiently protect certain routes and entity fields, leading to an access bypass that may financially impact the vendor.
    confidence_band: high
cves:
  - id: CVE-2026-118539
    kev_status: "false"
references:
  - https://www.securityweek.com/drupal-commerce-core-vulnerability-exploited-against-online-stores/
  - https://cyber.gc.ca/en/alerts-advisories/drupal-security-advisory-av26-1105
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Commerce Core to 3.3.13 or 8.x-2.41
      owner: IT Operations
      due: 24h
      evidence: Drupal advisory recommendation for CVE-2026-118539
  hunt_leads:
    - lead: Identify unauthorized changes or anomalies in commerce order state transitions
      technique_id: T1190
      data_needed:
        - Drupal database logs
        - Application audit logs
        - Order management system logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sites should audit their orders for inconsistencies as this vulnerability is being actively exploited
  mitigation_plan:
    - priority: immediate
      action: Update Drupal Commerce Core to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-118539
      evidence: Drupal security advisory
updates:
  - at: "2026-10-30T21:33:03Z"
    level: L3
    summary: exploited:true
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/drupal-security-advisory-av26-1105
---

Drupal has identified a highly critical access bypass vulnerability, tracked as CVE-2026-118539, affecting the Commerce Core module. The vulnerability allows unauthenticated attackers to exploit insufficient protection on specific routes and entity fields. The Drupal security team has assigned this issue a risk score of 21/25, noting that it is being actively exploited in the wild.

## Impact

The vulnerability poses a direct financial risk to vendors using the affected module. Exploitation may allow attackers to manipulate commerce-related data, including the checkout process and order states. Drupal specifically urges administrators to audit store orders for inconsistencies.

## Recommendation

- Upgrade the Drupal Commerce Core module to version 3.3.13 or 8.x-2.41 immediately.
- Review all commerce transactions and order logs for unauthorized changes, inconsistencies, or anomalies that occurred prior to patching.
- Audit Drupal instances for the presence of the vulnerable Commerce Core module versions if not already managed via centralized inventory.
