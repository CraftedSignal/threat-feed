---
title: Detection of Out-of-Domain Email Forwarding in Google Workspace
slug: 2024-01-gworkspace-email-forwarding
description: Detects automatic email forwarding to external domains in Google Workspace, which may indicate data leakage or misuse by malicious insiders or compromised accounts.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - data-leakage
  - gworkspace
  - email-forwarding
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login#email_forwarding_out_of_domain
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/login/gcp_gworkspace_out_of_domain_email_forwarding.yml
rules:
  - title: Google Workspace Out Of Domain Email Forwarding
    description: Detects automatic email forwarding to external domains in Google Workspace, which may indicate data leakage or misuse.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1114.003
    data_sources:
      - google_workspace
      - gcp
      - google_workspace.login
  - title: Google Workspace Potential Account Compromise via Email Forwarding Creation
    description: Detects potential account compromise activity when email forwarding rules are created to external domains.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1078
      - T1114.003
    data_sources:
      - google_workspace
      - gcp
      - google_workspace.login
rules_count: 2
---

This brief focuses on detecting unauthorized email forwarding to external domains within Google Workspace environments. The primary concern is the potential for data exfiltration or misuse by malicious insiders or threat actors who have compromised user accounts. The activity is logged by Google Workspace and can be monitored using the Google Workspace Admin Reports API. The event name associated with this activity is `email_forwarding_out_of_domain`, which is generated when a user configures…
