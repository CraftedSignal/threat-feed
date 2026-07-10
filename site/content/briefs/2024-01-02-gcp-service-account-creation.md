---
title: GCP Service Account Creation for Persistence
slug: 2024-01-02-gcp-service-account-creation
description: Successful creation of a new service account in Google Cloud Platform (GCP) can indicate malicious persistence, as adversaries may create these accounts to evade detection by avoiding standard user accounts.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - gcp
  - persistence
  - iam
vendors:
  - Google
products:
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://cloud.google.com/iam/docs/service-accounts
  - https://attack.mitre.org/techniques/T1136/
  - https://attack.mitre.org/techniques/T1136/003/
  - https://attack.mitre.org/tactics/TA0003/
rules:
  - title: GCP Service Account Created
    description: Detects when a new service account is created in Google Cloud Platform (GCP).
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - webserver
      - linux
  - title: GCP Service Account Created (Audit Logs)
    description: Detects when a new service account is created in Google Cloud Platform (GCP) using audit logs.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The creation of service accounts in Google Cloud Platform (GCP) is a common administrative task, but can be abused by attackers to maintain persistence. Service accounts are non-human accounts used by applications or VMs to make authorized API calls. Attackers may create service accounts to perform actions within a compromised GCP environment without relying on compromised user credentials, making their activities harder to track. The `google.iam.admin.v*.CreateServiceAccount` event indicates the creation of a new service account. Defenders should monitor for unexpected service account creation events, as they can signify unauthorized access or persistence mechanisms within a cloud environment.

## Attack Chain

1.  An attacker gains initial access to a GCP environment, possibly through compromised credentials or a vulnerable application.
2.  The attacker enumerates existing IAM roles and permissions to identify potential escalation paths.
3.  The attacker attempts to create a new service account using the `google.iam.admin.v*.CreateServiceAccount` API call.
4.  The attacker assigns elevated privileges to the newly created service account, granting it broad access to GCP resources.
5.  The attacker uses the service account to perform actions within the GCP environment, such as accessing data or modifying configurations.
6.  The attacker leverages the service account for persistence, allowing them to regain access even if their initial access method is revoked.
7.  The attacker monitors the service account activity to ensure it maintains its privileges and has not been detected.

## Impact

A successful attack can lead to unauthorized access to sensitive data, modification of critical system configurations, or disruption of services. Even though rated as "low" severity, successful exploitation could allow attackers to maintain a persistent presence within the GCP environment, potentially leading to significant data breaches or service outages.

## Recommendation

*   Deploy the Sigma rule `GCP Service Account Created` to your SIEM and tune for your environment to detect unexpected service account creation.
*   Review IAM policies and permissions regularly to identify and remove any excessive privileges granted to service accounts.
*   Implement multi-factor authentication (MFA) for all user accounts, including service accounts where possible, to prevent unauthorized access.
*   Monitor GCP audit logs for suspicious activity related to service account creation and usage, using the `event.action:google.iam.admin.v*.CreateServiceAccount` filter.
*   Implement automated workflows to validate and approve service account creation requests to ensure proper authorization and governance.
