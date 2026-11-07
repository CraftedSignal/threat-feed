---
brief_id: brief-2026-11-07-ibm-api-connect-ldap-injection
event_id: brief-2026-11-07-ibm-api-connect-ldap-injection
revision: 1
activity_at: "2026-11-07T05:55:48Z"
title: 'IBM API Connect: Unauthorized tenant access via LDAP injection (CVE-2026-17392)'
slug: 2026-11-ibm-api-connect-ldap-injection
description: IBM API Connect versions 10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2 contain an LDAP injection vulnerability that allows authenticated attackers to perform cross-tenant unauthorized administrative access.
date: "2026-11-07T05:55:48Z"
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
  - cpe:2.3:a:ibm:api_connect:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated remote attacker can exploit improper input sanitization in directory queries to manipulate query logic, potentially resulting in unauthorized administrative access to other tenants within the API Connect environment.
    confidence_band: high
cves:
  - id: CVE-2026-17392
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17392
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory IBM API Connect installations and verify if versions 10.0.8.0-10.0.8.12 or 12.1.0.0-12.1.1.2 are in use.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-17392 affected version ranges
  hunt_leads:
    - lead: Identify authenticated users executing unexpected administrative API calls or cross-tenant query patterns.
      technique_id: T1190
      data_needed:
        - API Connect audit logs
        - LDAP query logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows manipulation of directory queries to access other tenants.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches or upgrade to a version outside the affected ranges as soon as released by IBM.
      owner: IT Operations
      addresses: CVE-2026-17392
      evidence: IBM API Connect vulnerability disclosure
---

IBM API Connect contains an LDAP injection vulnerability due to improper neutralization of user-supplied input in directory queries. An authenticated remote attacker can exploit this flaw to manipulate the logic of LDAP queries, potentially leading to unauthorized administrative access to other tenants within the environment. As of the current disclosure, IBM has released advisory information; administrators should verify their current version against the affected ranges.

## Impact

The vulnerability allows an authenticated attacker to bypass standard authorization controls, resulting in unauthorized administrative access to tenants other than their own. The vulnerability is rated with a CVSS v3.1 base score of 9.9.

## Recommendation

- Identify all instances of IBM API Connect within the environment and verify current versioning.
- Review IBM security bulletins for the availability of patches addressing CVE-2026-17392.
- Monitor API Connect access logs for anomalous administrative behavior or high-frequency directory queries originating from standard user accounts.
