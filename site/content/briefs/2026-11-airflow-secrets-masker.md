---
brief_id: brief-2026-11-09-airflow-secrets-masker
event_id: brief-2026-11-09-airflow-secrets-masker
revision: 1
activity_at: "2026-11-09T09:13:21Z"
title: 'Apache Airflow: Secrets masker cleartext exposure (CVE-2026-113504)'
slug: 2026-11-airflow-secrets-masker
description: Apache Airflow versions prior to 3.4.0 fail to mask secrets nested deeper than five levels, potentially exposing sensitive data in plain text within task logs and rendered templates.
date: "2026-11-09T09:13:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*
vendors:
  - Apache Software Foundation
products:
  - Airflow (< 3.4.0)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: A user who can read task logs or rendered template fields may be exposed to cleartext secrets.
    confidence_band: high
cves:
  - id: CVE-2026-113504
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/599
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Apache Airflow to version 3.4.0 or later.
      owner: IT Operations
      due: 72h
      evidence: Vulnerability is addressed in Airflow 3.4.0.
  hunt_leads:
    - lead: Audit task logs and rendered templates for evidence of unexpectedly visible secret values.
      technique_id: T1592
      data_needed:
        - Airflow task logs
        - Rendered template field outputs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Secrets that appear more than five containers deep are shown in cleartext in task logs.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Airflow 3.4.0.
      owner: IT Operations
      addresses: CVE-2026-113504
      evidence: Affected versions include all versions before 3.4.0.
---

Apache Airflow contains a vulnerability in its secrets masker mechanism (CVE-2026-113504). The masker performs a depth-limited traversal, stopping after five levels of nested data structures. If a registered secret (such as a connection password or variable) resides deeper than five containers, the masker fails to redact it. This results in the secret appearing in cleartext within task logs and rendered template fields, which are accessible to users with task-log read permissions.

## Impact

Successful exploitation allows unauthorized users with access to view Airflow task logs or rendered templates to obtain sensitive credentials (e.g., database passwords, API keys) stored as Connections or Variables if those secrets are programmatically nested within deep data structures.

## Recommendation

- Upgrade Apache Airflow to version 3.4.0 or later immediately to resolve the masker depth limitation.
- Audit existing DAGs and custom operator implementations to identify deeply nested data structures passing sensitive information.
- Restrict access to task logs and template rendering to only authorized users until patching is complete.
