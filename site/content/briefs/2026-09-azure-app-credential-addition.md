---
title: Detection of Unauthorized Azure Application Credential Modifications
slug: 2026-09-azure-app-credential-addition
description: Detection of unauthorized credential addition to Microsoft Entra applications, a common technique for establishing persistence and escalating privileges in cloud environments.
date: "2026-09-03T13:36:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - cloud-security
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Microsoft Entra
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Any additional credentials added outside of expected processes could be a malicious actor using those credentials.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Detects when a new credential is added to an existing application.
    confidence_band: high
rules:
  - title: Detect Azure Application Credential Modification
    description: Detects when a new credential is added to an existing application, which may indicate unauthorized persistence or privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098.001
    data_sources:
      - audit_logs
      - azure
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to the SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for detecting credential additions in Entra
  mitigation_plan:
    - priority: medium_term
      action: Review all existing application credentials and revoke unused or unauthorized entries
      owner: Identity Operations
      addresses: T1098.001
      evidence: Microsoft Entra security operations architecture guidance
---

Monitoring the modification of Microsoft Entra (formerly Azure AD) application credentials is a critical defensive requirement. Threat actors often target service principals and applications to establish long-term persistence or escalate privileges by adding their own certificates or client secrets. By modifying existing applications, attackers can gain unauthorized access to protected resources, bypass conditional access policies, and maintain access even if user-level credentials are rotated. This intelligence highlights the need to baseline and alert on credential changes that occur outside of established DevOps workflows, infrastructure-as-code deployments, or authorized administrative actions.

## Impact

Successful modification of application credentials allows attackers to impersonate service principals, potentially resulting in unauthorized data exfiltration, service disruption, or further lateral movement within the cloud environment. Organizations failing to monitor these changes may remain unaware of persistent unauthorized access for extended periods.

## Recommendation

Deploy the following Sigma detection rule to Azure audit logs to identify credential updates. Tune the rule by correlating alerts against authorized deployment service principals or known maintenance windows to reduce false positives.

- Enable Azure Monitor or Log Analytics ingestion for Entra Audit Logs.
- Configure alerts based on the detection rule below to trigger for non-standard administrative accounts.
- Review existing application owners and credential lifecycle management practices.
