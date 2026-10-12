---
title: IDOR Vulnerability in TDuck Survey Form
slug: 2026-10-tduck-idor
description: TDuck survey form through 6.0 contains an insecure direct object reference vulnerability that allows authenticated users to delete other users' form submissions by supplying arbitrary submission identifiers.
date: "2026-10-12T13:43:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tduck:tduck_survey_form:*:*:*:*:*:*:*:*
tags:
  - web-application
  - idor
  - data-loss
  - impact
vendors:
  - TDuck
products:
  - TDuck survey form (<= 6.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: TDuck survey form through 6.0 contains an insecure direct object reference vulnerability that allows authenticated users to delete other users' form submissions.
    confidence_band: high
cves:
  - id: CVE-2026-109164
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109164
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review TDuck deployment version and confirm it is above 6.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109164 applies to versions through 6.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade TDuck survey form to the latest version
      owner: IT Operations
      addresses: CVE-2026-109164
      evidence: CVE-2026-109164 vulnerability in TDuck through 6.0
---

TDuck survey form, through version 6.0, contains an insecure direct object reference (IDOR) vulnerability (CVE-2026-109164) that enables authenticated users to perform unauthorized deletions of form submissions. By manipulating the submission identifier within requests, an attacker can target and remove data belonging to other users across the platform. The vulnerability exists due to a lack of sufficient access control checks when processing submission deletion requests, allowing an attacker to iterate through sequential identifiers. This flaw poses a significant risk to data integrity and availability, as attackers can perform platform-wide data destruction. Organizations utilizing TDuck survey form should verify current versions and restrict access to the affected submission deletion functionality.

## Impact

Successful exploitation of this vulnerability results in unauthorized data loss, where an attacker can delete arbitrary form submissions regardless of ownership. This impacts data integrity and historical record availability for organizations using the platform for surveys or data collection. The platform-wide scope of this flaw allows for mass deletion, potentially affecting the entire database of submissions.

## Recommendation

1. Upgrade to a version of TDuck survey form that addresses the IDOR vulnerability in the submission deletion logic.
2. Implement request monitoring to detect high volumes of deletion requests originating from a single authenticated user session.
3. Review access logs to identify anomalous deletion patterns, specifically those involving sequential numeric IDs.
4. Restrict access to the submission management portal to trusted, authorized administrators only until the vulnerability is patched.
