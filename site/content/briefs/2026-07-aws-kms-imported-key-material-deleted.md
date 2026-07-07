---
title: AWS KMS Imported Key Material Deleted
slug: 2026-07-aws-kms-imported-key-material-deleted
description: Adversaries leverage the `DeleteImportedKeyMaterial` API call against AWS KMS customer managed keys (CMKs) with external material, instantly rendering encrypted data inaccessible with no recovery window, facilitating cloud ransomware or data destruction attacks.
date: "2026-07-03T15:57:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - kms
  - data-destruction
  - ransomware
vendors:
  - Amazon Web Services
products:
  - AWS KMS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Deleting that material immediately makes the key unusable and renders all data encrypted under it inaccessible, with no recovery window. Adversaries may delete imported key material to sabotage recovery, destroy data, or hold encrypted resources for ransom.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteImportedKeyMaterial.html
  - https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
rules:
  - title: AWS KMS Imported Key Material Deleted
    description: Identifies the deletion of imported key material from an AWS KMS customer managed key via DeleteImportedKeyMaterial. This action immediately makes the key unusable and renders all data encrypted under it inaccessible, with no recovery window.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
      - T1485.001
    data_sources:
      - cloud
      - cloudtrail
rules_count: 1
---

This brief details a critical technique used by adversaries to achieve immediate and irreversible data destruction or to facilitate cloud ransomware within AWS environments. Adversaries exploit the `DeleteImportedKeyMaterial` API call against AWS Key Management Service (KMS) customer managed keys (CMKs) that use external key material (Bring Your Own Key - BYOK). Unlike standard key deletion processes which include a mandatory pending period, this action instantly renders the affected key unusable. Consequently, all data previously encrypted with this CMK becomes immediately inaccessible, with no built-in recovery window, presenting a significant threat to data availability and integrity. This technique is particularly dangerous due to its instant effect and potential for unrecoverable data loss if the original key material is not securely retained or an attacker withholds it.

## Attack Chain

1.  **Initial Compromise**: An adversary gains unauthorized access to an AWS account, often through compromised credentials, exposed API keys, or exploitation of a vulnerable service.
2.  **Reconnaissance & Privilege Escalation**: The adversary identifies AWS KMS keys with imported key material (BYOK) and elevates privileges to perform KMS actions, specifically `kms:DeleteImportedKeyMaterial`.
3.  **Key Identification**: The adversary identifies critical CMKs protecting sensitive data or essential services that are reliant on imported key material.
4.  **Material Deletion**: The adversary executes the `kms:DeleteImportedKeyMaterial` API call against targeted BYOK CMKs.
5.  **Data Inaccessibility**: The deletion immediately revokes access to the cryptographic key material, rendering all data encrypted by these CMKs instantly inaccessible.
6.  **Impact/Extortion**: The adversary either performs data destruction for sabotage purposes or demands a ransom for the re-importation of key material (if the attacker controls the material or a copy).

## Impact

Successful execution of the `DeleteImportedKeyMaterial` action results in immediate and potentially unrecoverable data loss across all services and data encrypted by the targeted AWS KMS customer managed key. This impact is instant, bypassing the standard grace period associated with `ScheduleKeyDeletion`. Organizations can face severe operational disruption, financial losses due to data inaccessibility, and potentially irrecoverable data if the original key material is not securely backed up or if the attacker withholds it during a ransomware scenario. The technique is used for both pure data destruction (sabotage) and cloud-specific ransomware campaigns, targeting the foundational security mechanism of cloud data protection.

## Recommendation

*   Enable AWS CloudTrail management events for KMS actions and ensure ingestion into your SIEM to collect relevant `aws.cloudtrail` logs.
*   Deploy the Sigma rule "AWS KMS Imported Key Material Deleted" in this brief to detect `kms:DeleteImportedKeyMaterial` calls.
*   Investigate alerts by examining `aws.cloudtrail.user_identity.arn`, `aws.cloudtrail.user_identity.access_key_id`, `aws.cloudtrail.user_identity.type`, `source.ip`, and `user_agent.original` fields in the generated `aws.cloudtrail` logs for unexpected activity.
*   Restrict `kms:DeleteImportedKeyMaterial` and `kms:ImportKeyMaterial` permissions to a minimal set of trusted administrative roles using IAM policies and AWS Organizations Service Control Policies (SCPs).
*   Maintain secure, offline backups of all imported key material (BYOK) to ensure recoverability in case of unauthorized deletion.
