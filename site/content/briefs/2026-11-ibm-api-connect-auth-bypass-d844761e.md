---
brief_id: brief-2026-11-07-ibm-api-connect-auth-bypass-d844761e
event_id: brief-2026-11-07-ibm-api-connect-auth-bypass-d844761e
revision: 1
activity_at: "2026-11-07T05:49:54Z"
title: 'IBM API Connect: Authorization bypass (CVE-2026-17049)'
slug: 2026-11-ibm-api-connect-auth-bypass-d844761e
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are vulnerable to an authorization bypass allowing remote authenticated attackers to access sensitive information and modify arbitrary documents.
date: "2026-11-07T05:49:54Z"
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
  validation_status: Needs environment validation to confirm API Connect versioning.
cpes:
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.1.2:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (12.1.0.0 through 12.1.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information and modify arbitrary documents due to authorization bypass through user-controlled keys.
    confidence_band: high
cves:
  - id: CVE-2026-17049
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17049
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch IBM API Connect to the latest version to address CVE-2026-17049.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability remediation requires software update.
  hunt_leads:
    - lead: Identify authenticated API requests involving unusual parameter modification or access to unauthorized document paths.
      technique_id: T1068
      data_needed:
        - API Connect audit logs
        - Access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Authorization bypass via user-controlled keys allows arbitrary document modification.
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a critical authorization bypass vulnerability (CVE-2026-17049). An attacker with existing authenticated access can manipulate user-controlled keys to bypass authorization checks, enabling unauthorized information disclosure and modification of arbitrary documents within the environment.

## Impact

Successful exploitation allows a remote authenticated attacker to read sensitive data and modify arbitrary documents, potentially leading to full compromise of data integrity and confidentiality within the API Connect environment.

## Recommendation

- Inventory all instances of IBM API Connect within the environment to identify versions 12.1.0.0 through 12.1.1.2.
- Apply the latest vendor security patches to remediate CVE-2026-17049 immediately.
- Review access logs and API audit trails for suspicious patterns of unauthorized document modification or unexpected data retrieval requests associated with authenticated user accounts.
