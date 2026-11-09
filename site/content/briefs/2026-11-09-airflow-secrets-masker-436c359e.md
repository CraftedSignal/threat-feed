---
brief_id: brief-2026-11-09-airflow-secrets-masker-436c359e
event_id: brief-2026-11-09-airflow-secrets-masker-436c359e
revision: 1
activity_at: "2026-11-09T09:13:26Z"
title: 'Apache Airflow: Sensitive information exposure via unmasked camelCase keys (CVE-2026-111452)'
slug: 2026-11-09-airflow-secrets-masker-436c359e
description: Apache Airflow versions prior to 3.4.0 fail to redact sensitive information in task logs, templates, and API responses when keys are formatted in camelCase, potentially exposing secrets to authorized users.
date: "2026-11-09T09:13:26Z"
type: advisory
types:
  - advisory
severities:
  - low
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
  - cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*
vendors:
  - Apache
products:
  - Airflow (< 3.4.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: A user who can read task... [can view] plaintext secrets that should have been masked by the system.
    confidence_band: high
cves:
  - id: CVE-2026-111452
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/595
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Apache Airflow to version 3.4.0 or later
      owner: IT Operations
      due: 7d
      evidence: Affected versions include Apache Airflow before 3.4.0
  hunt_leads:
    - lead: Identify access patterns to Airflow task logs or variables by unauthorized roles
      technique_id: T1552.001
      data_needed:
        - Airflow web server access logs
        - Airflow audit logs
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: A user who can read task... [can view] plaintext secrets
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Airflow to version 3.4.0
      owner: IT Operations
      addresses: CVE-2026-111452
      evidence: Apache Airflow before 3.4.0 is affected
---

Apache Airflow's secrets masker implementation contains a flaw where it only identifies sensitive key names in their snake_case format. Consequently, sensitive data stored under camelCase keys - specifically `privateKey`, `connectionString`, `webhookUrl`, or `accessKey` - are not properly redacted when appearing in task logs, rendered template fields, or API responses. This exposure impacts users who have access to view task logs or variables.

## Impact

Authorized users with read access to task logs, template fields, or API responses may be able to view plaintext secrets that were intended to be masked by the system.

## Recommendation

* Upgrade Apache Airflow to version 3.4.0 or later to address the secrets masking logic flaw.
* Audit existing Connection extras and Variables to identify if any sensitive data is currently stored under camelCase keys.
* Review access control policies for task logs and API endpoints to ensure that only authorized personnel can view sensitive workflow metadata.
