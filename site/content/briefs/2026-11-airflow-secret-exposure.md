---
brief_id: brief-2026-11-09-airflow-secret-exposure
event_id: brief-2026-11-09-airflow-secret-exposure
revision: 1
activity_at: "2026-11-09T09:14:06Z"
title: 'Apache Airflow: CLI command argument masking failure (CVE-2026-86468)'
slug: 2026-11-airflow-secret-exposure
description: Apache Airflow versions prior to 3.4.0 fail to mask secrets in CLI audit logs when using specific command arguments, allowing unauthorized access to plaintext credentials.
date: "2026-11-09T09:14:06Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
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
    evidence: A user who can read audit events but is denied... could recover plaintext credentials or secret configurations.
    confidence_band: high
cves:
  - id: CVE-2026-86468
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/588
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Apache Airflow to version 3.4.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Apache Airflow before 3.4.0
  hunt_leads:
    - lead: Hunt for historical audit log entries containing high-entropy strings following command-line flags identified as vulnerable.
      technique_id: T1552.001
      data_needed:
        - Audit log entries from Airflow
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Some supported command shapes leave secrets in cleartext, for example a trailing --description on Variable commands, --conn-extra, and the inline --password.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 3.4.0
      owner: IT Operations
      addresses: CVE-2026-86468
      evidence: Apache Airflow before 3.4.0
---

Apache Airflow versions prior to 3.4.0 contain a vulnerability where the CLI audit logging mechanism incorrectly handles secret masking. Certain CLI command shapes, specifically those utilizing `--conn-extra`, variable descriptions, and the inline `--password` flag in `airflow keycloak-auth-manager`, result in sensitive values being recorded in cleartext within audit logs. An authenticated user with permissions to read audit event logs may extract these secrets.

## Impact
Exposure of plaintext credentials and sensitive configuration data stored in the Airflow audit logs, potentially leading to unauthorized access to connected services or further lateral movement within the environment.

## Recommendation
- Upgrade Apache Airflow to version 3.4.0 or later immediately to apply the corrected CLI masking logic.
- Audit existing audit log stores for historical exposure of secret values referenced in the vulnerability (e.g., searches for `--conn-extra` or `--password` followed by high-entropy strings).
- Restrict access to Airflow audit logs to only highly privileged administrators to minimize the impact of the exposure.
