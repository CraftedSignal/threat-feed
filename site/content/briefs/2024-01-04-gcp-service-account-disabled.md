---
title: GCP Service Account Disabled
slug: 2024-01-04-gcp-service-account-disabled
description: Detection of a Google Cloud Platform (GCP) service account being disabled, potentially indicating malicious activity aimed at disrupting business operations by an adversary.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - gcp
  - cloud
  - iam
  - impact
vendors:
  - Google
products:
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
references:
  - https://cloud.google.com/iam/docs/service-accounts
  - https://attack.mitre.org/techniques/T1531/
rules:
  - title: GCP Service Account Disabled
    description: Detects when a service account is disabled in Google Cloud Platform (GCP).
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - webserver
      - linux
  - title: GCP Service Account Disabled - Audit Logs
    description: Detects when a service account is disabled in Google Cloud Platform (GCP) based on audit logs
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This alert identifies when a service account is disabled within Google Cloud Platform (GCP). Service accounts are non-human accounts utilized by applications and virtual machines for authorized API calls. An attacker compromising an account with sufficient privileges may disable a service account to disrupt services, impacting business operations. The rule focuses on detecting successful disablement actions in GCP audit logs, specifically targeting the `google.iam.admin.v*.DisableServiceAccount` event. This detection enables security teams to promptly investigate and respond to potentially malicious activity. The alert logic covers all Google Cloud Platform environments.

## Attack Chain

1.  An attacker gains unauthorized access to a GCP account with sufficient IAM privileges.
2.  The attacker enumerates existing service accounts within the targeted GCP project.
3.  The attacker identifies a service account critical to business operations.
4.  The attacker executes the `google.iam.admin.v*.DisableServiceAccount` API call to disable the target service account.
5.  GCP audit logs record the successful disablement of the service account with `event.outcome:success`.
6.  Applications or VMs relying on the disabled service account experience service disruptions or failures.
7.  The attacker may attempt to further exploit the disruption to escalate privileges or conduct lateral movement.

## Impact

Disabling a GCP service account can lead to significant disruption of cloud-based applications and services that rely on the account for authentication and authorization. This can result in application downtime, data access failures, and impaired business operations. The severity depends on the criticality of the disabled service account. The impact ranges from temporary service interruptions to complete application failures, potentially affecting customer-facing services and internal business processes.

## Recommendation

*   Deploy the Sigma rule "GCP Service Account Disabled" to your SIEM to detect this activity in real-time, and tune for your environment.
*   Review the GCP audit logs for the specific event `event.action:google.iam.admin.v*.DisableServiceAccount` to identify the source of the disablement action.
*   Implement additional monitoring and alerting for similar disablement actions on service accounts to detect and respond to future incidents promptly.
*   Ensure that the principle of least privilege is applied to all service accounts, and enforce MFA for privileged accounts.
*   Monitor GCP audit logs for anomalous activity related to IAM roles and permissions.
