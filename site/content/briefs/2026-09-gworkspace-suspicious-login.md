---
title: Detection of Google Workspace Suspicious Login Events
slug: 2026-09-gworkspace-suspicious-login
description: Google Workspace audit logs identify suspicious authentication attempts including unauthorized application access, programmatic login anomalies, and general suspicious sign-in events.
date: "2026-09-24T12:13:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity-security
  - gcp
  - gworkspace
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The rule identifies suspicious login activity involving cloud accounts as classified by Google's authentication telemetry.
    confidence_band: high
references:
  - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login#suspicious_login
rules:
  - title: Detect Google Workspace Suspicious Login Events
    description: Detects Google Workspace login activity that is explicitly classified as suspicious or anomalous by Google's audit telemetry.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - webserver
      - gcp
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable and ingest Google Workspace audit logs into SIEM
      owner: SOC
      due: 48h
      evidence: Source documentation for GWorkspace audit logging
  hunt_leads:
    - lead: Historical search for 'suspicious_login' event names over the last 30 days
      technique_id: T1078.004
      data_needed:
        - GCP audit log history
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The detection rule triggers on these events; historical data will confirm prior unauthorized activity.
---

Google Workspace maintains audit logs that categorize specific login activities as suspicious based on Google's internal heuristics. These events, reported via the 'login.googleapis.com' service within GCP/Workspace audit logs, flag sign-in attempts that deviate from established patterns or violate security policies. Specifically, the system identifies three primary categories: standard suspicious logins, usage of less secure applications, and anomalous programmatic login patterns. Monitoring these audit events is critical for detecting potential account takeover, credential harvesting, or automated abuse by malicious actors targeting corporate identities. Defenders should ingest these audit logs to identify compromised accounts, unauthorized third-party integrations, and automated exploitation of service accounts.

## Impact

Successful exploitation of account credentials or programmatic interfaces can lead to unauthorized data exfiltration, persistent access to organizational resources, and the use of the corporate environment as a platform for further lateral movement or phishing campaigns.

## Recommendation

1. Configure GCP Admin Audit logs to export 'login.googleapis.com' event data to a centralized SIEM or security data lake.
2. Deploy the Sigma detection rule below to flag and alert on 'suspicious_login', 'suspicious_login_less_secure_app', and 'suspicious_programmatic_login' event names.
3. Perform regular reviews of flagged accounts to distinguish between malicious activity and misconfigured but legitimate legacy applications.
