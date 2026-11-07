---
brief_id: brief-2026-11-07-ibm-api-connect-sql-injection-c6654e73
event_id: brief-2026-11-07-ibm-api-connect-sql-injection-c6654e73
revision: 1
activity_at: "2026-11-07T05:56:01Z"
title: 'IBM API Connect: SQL injection vulnerability (CVE-2026-17396)'
slug: 2026-11-ibm-api-connect-sql-injection-c6654e73
description: A SQL injection vulnerability in IBM API Connect allows remote authenticated attackers to access sensitive information, carrying a CVSS base score of 9.6.
date: "2026-11-07T05:56:01Z"
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
  validation_status: Ready for internal environment scan
cpes:
  - cpe:2.3:a:ibm:api_connect:10.0.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: IBM API Connect ... could allow a remote authenticated attacker to obtain sensitive information due to SQL injection.
    confidence_band: high
cves:
  - id: CVE-2026-17396
    cvss: 9.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17396
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory IBM API Connect instances and correlate with vulnerable versions identified in CVE-2026-17396
      owner: IT Operations
      due: 24h
      evidence: Vulnerable versions are explicitly named in the CVE advisory
  hunt_leads:
    - lead: Identify authenticated API requests containing SQL syntax patterns or unexpected query parameters
      technique_id: T1505
      data_needed:
        - API management access logs
        - Web server request logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: SQL injection vulnerability in IBM API Connect
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a SQL injection vulnerability. A remote authenticated attacker can exploit this flaw to gain unauthorized access to sensitive information stored within the application database. 

## Impact
Successful exploitation allows for the unauthorized retrieval of sensitive data, posing a critical risk to data confidentiality within the affected API management environments.

## Recommendation
- Inventory all deployed instances of IBM API Connect to identify versions within the affected ranges (10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2).
- Monitor IBM security bulletins for the release of patches or configuration-based mitigations for CVE-2026-17396.
- Implement strict input validation and parameterized queries for all custom API development performed on the IBM API Connect platform to reduce the surface area for SQL injection.
