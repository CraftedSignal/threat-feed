---
title: Google Workspace Suspicious Login Activity
slug: 2024-01-26-gworkspace-suspicious-login
description: Detect Google Workspace login activity that Google has classified as suspicious, potentially indicating initial access, privilege escalation, defense evasion, or persistence attempts.
date: "2024-01-26T10:00:00Z"
severities:
  - medium
tags:
  - initial-access
  - privilege-escalation
  - defense-evasion
  - persistence
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
references:
  - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging
  - https://cloud.google.com/logging/docs/audit/understanding-audit-logs
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login#suspicious_login
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login#suspicious_login_less_secure_app
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login#suspicious_programmatic_login
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/login/gcp_gworkspace_suspicious_login.yml
rules:
  - title: Gworkspace Suspicious Login Less Secure App
    description: Detects Google Workspace login activity classified as suspicious due to the use of less secure app.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1078.004
    data_sources:
      - gcp
      - google_workspace.login
  - title: Gworkspace Suspicious Programmatic Login
    description: Detects Google Workspace login activity classified as suspicious programmatic login.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1078.004
    data_sources:
      - gcp
      - google_workspace.login
  - title: Gworkspace Suspicious Login
    description: Detects Google Workspace login activity classified as suspicious login.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1078.004
    data_sources:
      - gcp
      - google_workspace.login
rules_count: 3
---

This brief focuses on detecting suspicious login activity within Google Workspace environments, as flagged by Google's internal risk assessment mechanisms. Google Workspace logs login events and classifies them based on various risk factors, including the use of less secure applications, programmatic logins, and other anomalies. This detection capability is crucial for identifying potential compromises, unauthorized access attempts, and malicious activities within the Google Workspace…
