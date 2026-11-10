---
brief_id: brief-2026-11-10-dolibarr-idor
event_id: brief-2026-11-10-dolibarr-idor
revision: 1
activity_at: "2026-11-10T18:27:53Z"
title: 'Dolibarr: Insecure Direct Object Reference in expense report API (CVE-2026-125754)'
slug: 2026-11-dolibarr-idor
description: An IDOR vulnerability in the Dolibarr expense report API allows authenticated users with minimal privileges to access and manipulate payment records belonging to other users.
date: "2026-11-10T18:27:53Z"
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
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:dolibarr:dolibarr:*:*:*:*:*:*:*:*
tags:
  - idor
  - api-vulnerability
  - financial-system
  - vulnerability
vendors:
  - Dolibarr
products:
  - Dolibarr (20.0.0-23.0.4)
  - Dolibarr (< 24.0.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers with only expense report read and create rights can call getAllPayments, getPayments, addPayment, or updatePayment to read, create, or modify payments.
    confidence_band: high
cves:
  - id: CVE-2026-125754
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125754
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Dolibarr to version 24.0.2 or later
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-125754 vendor fix version
  hunt_leads:
    - lead: Identify unauthorized API calls to expense report payment endpoints
      data_needed:
        - Dolibarr access logs
        - Web server logs (POST/GET requests to api_expensereports.class.php)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability resides in api_expensereports.class.php payment endpoints
  mitigation_plan:
    - priority: immediate
      action: Restrict API access for non-privileged users until patching is complete
      owner: IT Operations
      addresses: CVE-2026-125754
      evidence: Exploitation allows authenticated users to access other users payment records
---

Dolibarr versions 20.0.0 through 23.0.4 and 24.x before 24.0.2 contain an insecure direct object reference (IDOR) vulnerability in the `api_expensereports.class.php` component. Authenticated users with restricted "read" and "create" permissions for expense reports can interact with endpoints, including `getAllPayments`, `getPayments`, `addPayment`, or `updatePayment`, to access, create, or modify payments belonging to other users. This may result in unauthorized financial data exposure and the falsification of reimbursement states.

## Impact
The vulnerability allows authenticated users to read sensitive financial data and manipulate reimbursement records, potentially leading to unauthorized financial gain or corruption of accounting data within the Dolibarr instance.

## Recommendation
- Upgrade Dolibarr to version 24.0.2 or later to patch the vulnerable payment endpoints.
- Review application access logs for unexpected access patterns to `api_expensereports.class.php` associated with non-administrative user accounts.
- Audit expense report payment history for anomalous entries or modifications performed by users outside of the finance department or the specific report owner.
