---
title: GCP Service Account Key Creation for Persistence
slug: 2024-01-03-gcp-service-account-key-creation
description: An adversary may create a new key for a service account in Google Cloud Platform (GCP) to abuse the permissions assigned to that account and evade detection, potentially leading to persistent access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - gcp
  - persistence
  - account-manipulation
vendors:
  - Google
products:
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://cloud.google.com/iam/docs/service-accounts
  - https://cloud.google.com/iam/docs/creating-managing-service-account-keys
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/001/
  - https://attack.mitre.org/tactics/TA0003/
rules:
  - title: GCP Service Account Key Creation
    description: Detects the creation of a new service account key in Google Cloud Platform.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1098
      - T1098.001
    data_sources:
      - cloudtrail
      - gcp
  - title: GCP Service Account Key Creation via gcloud CLI
    description: Detects service account key creation using the gcloud CLI tool.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
      - T1098.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This rule detects the creation of new keys for service accounts within Google Cloud Platform (GCP). Service accounts are non-human accounts used by applications and virtual machines to make authorized API calls. While legitimate key creation is a common administrative task, malicious actors may create new keys to gain unauthorized access and persist within a GCP environment. Successful exploitation allows an attacker to leverage the permissions associated with the service account, potentially leading to data exfiltration, resource manipulation, or further lateral movement. The detection focuses on monitoring GCP audit logs for key creation events.

## Attack Chain

1.  An attacker gains initial access to a GCP environment through compromised credentials or a vulnerable service.
2.  The attacker enumerates existing service accounts to identify targets with desirable permissions.
3.  The attacker attempts to create a new key for a chosen service account using the `google.iam.admin.v*.CreateServiceAccountKey` API.
4.  The key creation is successful, granting the attacker access to the service account.
5.  The attacker uses the new key to authenticate as the service account.
6.  The attacker leverages the service account's permissions to access sensitive data or resources within GCP.
7.  The attacker may create additional keys for redundancy and persistence.
8.  The attacker maintains long-term access to the compromised GCP environment, potentially causing significant damage.

## Impact

Successful exploitation allows an attacker to leverage the service account's permissions, potentially leading to data exfiltration, resource manipulation, or further lateral movement within the GCP environment. While the severity is low, repeated or unusual key creations, particularly for highly privileged service accounts, can indicate a serious compromise. The lack of proper tracking and management of service account keys significantly increases the risk of unauthorized access and persistence.

## Recommendation

*   Deploy the Sigma rule "GCP Service Account Key Creation" to your SIEM and tune for your environment to detect suspicious key creation activity in GCP.
*   Review the audit logs for the specific event.action `google.iam.admin.v*.CreateServiceAccountKey` to identify the service account involved in the key creation.
*   Implement additional monitoring and alerting for unusual service account activities, such as unexpected key creations or permission changes, to enhance detection of similar threats in the future (as described in the "Setup" section).
*   Rotate all keys associated with the affected service account if unauthorized access is suspected to mitigate further risk (as mentioned in the "Response and remediation" section).
