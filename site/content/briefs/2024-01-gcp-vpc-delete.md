---
title: GCP Virtual Private Cloud Network Deletion
slug: 2024-01-gcp-vpc-delete
description: Detection of Virtual Private Cloud (VPC) network deletion in Google Cloud Platform (GCP), which can be used by an adversary to disrupt a target's network and business operations.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - gcp
  - defense-evasion
  - impact
vendors:
  - Google
products:
  - Virtual Private Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://cloud.google.com/vpc/docs/vpc
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/007/
  - https://attack.mitre.org/techniques/T1485/
  - https://attack.mitre.org/tactics/TA0005/
  - https://attack.mitre.org/tactics/TA0040/
rules:
  - title: GCP VPC Network Deletion
    description: Detects deletion of a Virtual Private Cloud (VPC) network in Google Cloud Platform (GCP).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
      - T1562
    data_sources:
      - cloudtrail
      - gcp
      - compute
  - title: GCP VPC Network Deletion by Unusual User
    description: Detects deletion of a VPC network by a user account that typically does not perform this action.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
      - T1562
    data_sources:
      - cloudtrail
      - gcp
      - compute
rules_count: 2
---

This rule identifies when a Virtual Private Cloud (VPC) network is deleted in Google Cloud Platform (GCP). A VPC network is a virtual version of a physical network within a GCP project, containing subnets, routes, and firewalls. An adversary may delete a VPC network to disrupt a target's network and business operations. The detection rule monitors audit logs for successful VPC deletions, flagging potential malicious activity by correlating specific event actions and outcomes. The rule is based on Elastic's detection rule with ID c58c3081-2e1d-4497-8491-e73a45d1a6d6, and updated on 2026/04/10. It focuses on identifying actions that could lead to defense evasion and impact through data destruction.

## Attack Chain

1. An attacker gains unauthorized access to a GCP account with sufficient privileges. This could be via compromised credentials, or a misconfigured IAM role.
2. The attacker enumerates available VPC networks within the GCP project to identify a target for disruption.
3. The attacker executes a command or API call to initiate the deletion of the chosen VPC network. This could be done via the gcloud CLI or the GCP console.
4. GCP validates the attacker's permissions and initiates the VPC network deletion process.
5. The VPC network and all associated resources (subnets, routes, firewall rules) are removed from the GCP environment.
6. Applications and services relying on the deleted VPC network experience connectivity issues and service disruptions.
7. The attacker monitors the impact of the VPC network deletion to ensure the desired disruption has occurred.
8. The attacker attempts to cover their tracks by deleting audit logs or other evidence of their actions.

## Impact

Successful deletion of a VPC network can severely disrupt business operations. Applications and services relying on the deleted network will experience connectivity issues and may become unavailable. This can lead to data loss, financial losses, and reputational damage. The severity depends on the criticality of the affected applications and the speed of recovery. While specific numbers of victims are not provided, the impact can range from isolated application failures to widespread outage affecting entire organizations depending on their GCP infrastructure.

## Recommendation

*   Deploy the `GCP VPC Network Deletion` Sigma rule to your SIEM to detect unauthorized VPC network deletions. Ensure the log source is configured to ingest GCP audit logs.
*   Review and harden IAM policies to enforce the principle of least privilege for VPC network management.
*   Monitor GCP audit logs for unusual activity related to VPC network configurations, focusing on the `event.action:v*.compute.networks.delete` event.
*   Implement multi-factor authentication (MFA) for all GCP accounts with administrative privileges.
*   Create exceptions in the `GCP VPC Network Deletion` rule for authorized and expected VPC network deletions.
