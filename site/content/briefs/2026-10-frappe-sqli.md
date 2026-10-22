---
brief_id: brief-2026-10-22-frappe-sqli
event_id: brief-2026-10-22-frappe-sqli
revision: 1
activity_at: "2026-10-22T03:53:16Z"
title: 'Frappe Framework: Blind SQL injection (CVE-2026-114664)'
slug: 2026-10-frappe-sqli
description: Frappe Framework versions prior to 16.33.0 contain a blind SQL injection vulnerability in the get_events method, allowing authenticated attackers to extract sensitive database content.
date: "2026-10-22T03:53:16Z"
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
  validation_status: No vendor-provided IOCs or specific log patterns identified; relies on application-level patch.
cpes:
  - cpe:2.3:a:frappe:frappe_framework:*:*:*:*:*:*:*:*
vendors:
  - Frappe
products:
  - Frappe Framework (< 16.33.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated attackers can send crafted input to get_events and infer query results from application behavior to extract sensitive database information.
    confidence_band: high
cves:
  - id: CVE-2026-114664
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114664
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Frappe Framework to version 16.33.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability remediated in version 16.33.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Frappe Framework to 16.33.0
      owner: IT Operations
      addresses: CVE-2026-114664
      evidence: NVD advisory states fixed in 16.33.0.
---

Frappe Framework before 16.33.0 contains a blind SQL injection vulnerability in the frappe.desk.doctype.event.event.get_events method. The vulnerability arises from the failure to properly neutralize user-supplied input before it is included in SQL queries. An authenticated attacker can send crafted input to the affected method and infer query results based on the application's response, leading to the unauthorized exfiltration of database contents.

## Impact
Successful exploitation allows an authenticated attacker to perform blind SQL injection, which can lead to the unauthorized extraction of sensitive data from the underlying database.

## Recommendation
- Upgrade the Frappe Framework to version 16.33.0 or later to remediate this vulnerability.
- Review web server access logs for anomalous requests targeting the 'frappe.desk.doctype.event.event.get_events' endpoint.
- Implement strict input validation and parameterized queries for all database interaction methods if upgrading is not immediately possible.
