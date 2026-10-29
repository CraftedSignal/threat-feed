---
brief_id: brief-2026-10-29-openemr-sql-injection
event_id: brief-2026-10-29-openemr-sql-injection
revision: 1
activity_at: "2026-10-29T17:30:52Z"
title: 'OpenEMR: Authenticated SQL injection (CVE-2026-49142)'
slug: 2026-10-openemr-sql-injection
description: OpenEMR versions prior to 8.5.0 contain an authenticated SQL injection vulnerability in the Syndromic Surveillance module, enabling Clinician-level users to perform error-based data exfiltration and administrative account takeover.
date: "2026-10-29T17:30:52Z"
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
  validation_status: Source supported; environment validation pending
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenEMR before 8.5.0 contains an authenticated SQL injection vulnerability in the Syndromic Surveillance module that allows users... to read and modify arbitrary database contents.
    confidence_band: high
cves:
  - id: CVE-2026-49142
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49142
rules:
  - title: Detect CVE-2026-49142 Exploitation - SQL Injection in Syndromic Surveillance
    description: Detects exploitation attempts against the Syndromic Surveillance module by monitoring POST requests to the index endpoint containing SQL injection patterns in the form_icd_codes parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenEMR to version 8.5.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-49142 advisory
  hunt_leads:
    - lead: Search web logs for anomalous SQL keywords in form_icd_codes parameter
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source details injection method via form_icd_codes parameter
  mitigation_plan:
    - priority: immediate
      action: Upgrade to OpenEMR 8.5.0
      owner: IT Operations
      addresses: CVE-2026-49142
      evidence: NVD advisory for CVE-2026-49142
---

OpenEMR versions before 8.5.0 are vulnerable to an authenticated SQL injection flaw within the Syndromic Surveillance module. An attacker with Clinician-level privileges can manipulate the 'form_icd_codes[]' POST parameter to perform error-based exfiltration using MySQL 'extractvalue()' or execute stacked queries to modify database contents. This can lead to the theft of password hashes and complete administrative account takeover.

## Impact

Successful exploitation allows authenticated users to read sensitive database contents, including bcrypt password hashes, and modify records to reset administrative accounts, leading to full system compromise.

## Recommendation

* Patch OpenEMR to version 8.5.0 or later.
* Audit access logs for abnormal POST requests directed at the 'syndromicsurveillance/index' endpoint by users with 'Clinician' or lower privileges.
* Monitor database error logs for occurrences of 'extractvalue()' related errors that may indicate failed or successful injection attempts.
