---
brief_id: brief-2026-11-08-openemr-sqli
event_id: brief-2026-11-08-openemr-sqli
revision: 1
activity_at: "2026-11-08T21:26:25Z"
title: 'OpenEMR: SQL injection in Fee Sheet drug-inventory lookup (CVE-2026-124469)'
slug: 2026-11-openemr-sqli
description: OpenEMR versions prior to 8.3.0 are susceptible to time-based blind SQL injection in the Fee Sheet component, allowing low-privileged authenticated users to exfiltrate patient data and user hashes.
date: "2026-11-08T21:26:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - health-sector
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenEMR before 8.3.0 contains an SQL injection vulnerability in the Fee Sheet drug-inventory lookup.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Low-privileged authenticated users can submit Fee Sheet product lines with constant subqueries to run a time-based blind oracle, extracting patient data and users_secure bcrypt hashes.
    confidence_band: high
cves:
  - id: CVE-2026-124469
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124469
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenEMR to version 8.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability addressed in OpenEMR 8.3.0
  hunt_leads:
    - lead: Identify authenticated sessions performing frequent, time-delayed POST requests to drug-inventory lookup endpoints
      technique_id: T1190
      data_needed:
        - Web server logs (access and error logs)
        - Application-level auditing of the Fee Sheet module
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Low-privileged authenticated users can submit Fee Sheet product lines with constant subqueries to run a time-based blind oracle
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenEMR to 8.3.0
      owner: IT Operations
      addresses: CVE-2026-124469
      evidence: Source notes version 8.3.0 resolution
---

OpenEMR versions before 8.3.0 contain an SQL injection vulnerability in the `DrugSalesService::sellDrug` method. The vulnerability arises from improper sanitization of the `prod[N][warehouse]` POST field before it is used in an `ORDER BY` clause. An authenticated attacker with low privileges can leverage this flaw to perform time-based blind SQL injection attacks to exfiltrate sensitive data, such as patient records and bcrypt hashes of user credentials.

## Impact

Successful exploitation allows authenticated attackers to perform unauthorized data extraction, leading to the compromise of patient PII and user authentication data (bcrypt hashes).

## Recommendation

* Upgrade to OpenEMR version 8.3.0 or later to address the vulnerability.
* Audit access logs for abnormal POST request patterns to the `DrugSalesService` or Fee Sheet-related endpoints containing SQL injection syntax, particularly within the `prod[N][warehouse]` parameter.
