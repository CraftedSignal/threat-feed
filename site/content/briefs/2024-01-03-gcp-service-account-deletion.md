---
title: GCP Service Account Deletion
slug: 2024-01-03-gcp-service-account-deletion
description: Detection of Google Cloud Platform (GCP) service account deletion, which adversaries may perform to disrupt business operations.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - gcp
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
rules:
  - title: GCP Service Account Deletion Detected
    description: Detects when a service account is deleted in Google Cloud Platform.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - gcp_audit
      - gcp
  - title: GCP Service Account Deletion by Unusual User
    description: Detects GCP service account deletion events initiated by a user or service account not typically associated with such actions.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - gcp_audit
      - gcp
rules_count: 2
---

This alert detects the deletion of service accounts within Google Cloud Platform (GCP). Service accounts are non-human identities used by applications and virtual machines to interact with GCP services. An attacker may delete these accounts to disrupt legitimate applications, severing their access to critical resources and services. Monitoring for this activity is essential because while legitimate administrative actions can lead to service account deletion, unauthorized or malicious deletions can have significant operational impact. This detection focuses on successful `google.iam.admin.v*.DeleteServiceAccount` events within GCP audit logs.

## Attack Chain

1.  The attacker gains unauthorized access to a GCP account, potentially through compromised credentials or exploiting a misconfigured IAM role.
2.  The attacker enumerates existing service accounts within the GCP project to identify potential targets for disruption.
3.  The attacker selects a target service account based on its perceived importance or impact on the target organization's operations.
4.  The attacker executes the `google.iam.admin.v*.DeleteServiceAccount` API call via the gcloud CLI or GCP console.
5.  GCP successfully processes the delete request and removes the service account identity.
6.  Applications and VMs relying on the deleted service account lose access to authorized GCP services.
7.  The target organization experiences disruption in services, leading to potential data loss, operational downtime, or financial repercussions.

## Impact

A successful service account deletion can lead to significant disruption within a GCP environment. Depending on the permissions granted to the deleted service account, the impact could range from a minor service outage to a complete shutdown of critical applications. Organizations relying heavily on GCP for their infrastructure are especially vulnerable. If a critical service account is deleted, it can take considerable time to restore functionality, leading to potential financial loss and reputational damage. The number of affected victims depends on the scope of the targeted service account.

## Recommendation

*   Deploy the Sigma rule `GCP Service Account Deletion Detected` to your SIEM and tune for your environment to detect malicious deletions.
*   Review the audit logs for the specific `event.action:google.iam.admin.v*.DeleteServiceAccount` to identify the exact time and source of the deletion.
*   Investigate the context of the deleted service account, including its permissions and the resources it had access to.
