---
title: GCP IAM Service Account Key Deletion
slug: 2024-01-gcp-iam-key-deletion
description: Detection of Identity and Access Management (IAM) service account key deletion in Google Cloud Platform (GCP), potentially indicating malicious activity such as disrupting services or covering tracks after unauthorized access.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - gcp
  - iam
  - persistence
  - impact
vendors:
  - Google
products:
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
references:
  - https://cloud.google.com/iam/docs/service-accounts
  - https://cloud.google.com/iam/docs/creating-managing-service-account-keys
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1531/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/tactics/TA0040/
rules:
  - title: GCP IAM Service Account Key Deletion
    description: Detects the deletion of a Google Cloud Platform (GCP) IAM service account key.
    platform: sigma
    severity: low
    tactics:
      - impact
      - persistence
    techniques:
      - T1531
    data_sources:
      - cloudtrail
      - gcp
  - title: GCP IAM Service Account Key Deletion - Non Success
    description: Detects attempts to delete a Google Cloud Platform (GCP) IAM service account key, even if the deletion was not successful.
    platform: sigma
    severity: informational
    tactics:
      - impact
      - persistence
    techniques:
      - T1531
    data_sources:
      - cloudtrail
      - gcp
rules_count: 2
---

This alert identifies the deletion of an Identity and Access Management (IAM) service account key within Google Cloud Platform (GCP). Each service account relies on a pair of public/private RSA keys for authentication. Deleting a key prevents associated applications from accessing Google Cloud resources. While regular key rotation is a security best practice, unauthorized or unexpected key deletions can indicate malicious activity, such as attempts to disrupt services or conceal unauthorized access. This detection focuses on successful key deletions as logged in GCP audit logs.

## Attack Chain

1.  An attacker gains unauthorized access to a GCP account through compromised credentials or a misconfigured IAM policy.
2.  The attacker enumerates existing service accounts to identify potential targets for disruption or privilege escalation.
3.  The attacker selects a service account with the intent to disrupt dependent applications or services.
4.  The attacker executes the `google.iam.admin.v*.DeleteServiceAccountKey` API call to delete the key associated with the targeted service account.
5.  The GCP audit logs record a successful deletion event (`event.outcome: success`).
6.  Legitimate applications or services that rely on the deleted service account key fail to authenticate, leading to service disruption.
7.  The attacker may attempt to further compromise the environment or exfiltrate data, taking advantage of the chaos and confusion caused by the disruption.

## Impact

Successful deletion of a service account key can disrupt critical applications and services relying on that key for authentication and authorization. The severity of the impact depends on the importance of the affected service account and the scope of its access. While the specific number of affected organizations is unknown, a successful attack could lead to temporary outages, data unavailability, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `GCP IAM Service Account Key Deletion` to your SIEM to detect unauthorized key deletions.
*   Investigate any alerts triggered by the `GCP IAM Service Account Key Deletion` Sigma rule, paying close attention to the actor, affected service account, and context of the deletion event.
*   Review IAM policies and service account permissions to minimize the blast radius of compromised service accounts.
*   Enforce multi-factor authentication (MFA) for all GCP user accounts to reduce the risk of credential compromise.
*   Implement regular service account key rotation policies and monitor for deviations from established baselines.
