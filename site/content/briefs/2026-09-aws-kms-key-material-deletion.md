---
title: Abuse of AWS KMS DeleteImportedKeyMaterial for Data Sabotage
slug: 2026-09-aws-kms-key-material-deletion
description: Adversaries can perform immediate data destruction in AWS by invoking the DeleteImportedKeyMaterial API, rendering all data protected by external-origin (BYOK) keys inaccessible without a recovery window.
date: "2026-09-18T19:35:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - kms
  - impact
  - sabotage
vendors:
  - Amazon
products:
  - AWS KMS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Deleting that material immediately makes the key unusable and renders all data encrypted under it inaccessible, with no recovery window.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteImportedKeyMaterial.html
  - https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
rules:
  - title: Detect AWS KMS Imported Key Material Deletion
    description: Detects the deletion of imported key material via DeleteImportedKeyMaterial, which results in instant, unrecoverable data inaccessibility if the material is not securely retained.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor KMS key material deletion
      owner: Detection Engineering
      due: 48h
      evidence: This action provides visibility into potentially destructive key management operations.
  enrichment_needed:
    - item: Identify all keys with external-origin (BYOK) in the environment
      owner: Cloud Security
      reason: To prioritize monitoring of keys with high impact if destroyed.
      evidence: Understanding the scope of BYOK usage is critical for risk assessment.
  hunt_leads:
    - lead: Search CloudTrail for any successful DeleteImportedKeyMaterial events in the last 30 days
      technique_id: T1485
      data_needed:
        - CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unusual activity in this API is highly indicative of potential sabotage.
  mitigation_plan:
    - priority: immediate
      action: Apply SCPs to restrict kms:DeleteImportedKeyMaterial and kms:ImportKeyMaterial
      owner: IAM Engineering
      addresses: T1485
      evidence: Restrictive policies prevent unauthorized destruction of keys.
  gaps:
    - Limited visibility if CloudTrail management events are disabled.
---

Adversaries are targeting AWS Key Management Service (KMS) environments by invoking the 'DeleteImportedKeyMaterial' API action on customer-managed keys that rely on imported key material (Bring Your Own Key - BYOK). Unlike the standard 'ScheduleKeyDeletion' process, which enforces a mandatory waiting period of 7 to 30 days, 'DeleteImportedKeyMaterial' executes instantly. This action transitions the target key to a 'PendingImport' state, effectively ceasing all cryptographic operations. Data encrypted under these keys becomes immediately inaccessible. If the original key material is not retained by the customer, this action results in permanent data loss. This technique is observed in the context of cloud-based ransomware and sabotage operations, where attackers aim to destroy data or hold it for ransom by controlling the availability of the decryption material. Defenders must treat this action as a high-risk destructive primitive, particularly when triggered by non-service principals.

## Attack Chain

1. Attacker gains persistence or elevates privileges within the AWS cloud environment.
2. Attacker enumerates existing KMS keys to identify those with an external origin (BYOK).
3. Attacker evaluates the target key's permissions to ensure they possess 'kms:DeleteImportedKeyMaterial' capabilities.
4. Attacker identifies critical encrypted assets (S3 buckets, EBS volumes, or RDS databases) protected by the targeted KMS keys.
5. Attacker executes the 'DeleteImportedKeyMaterial' API call against the chosen KMS keys.
6. The target key enters 'PendingImport' state, causing immediate decryption failures across dependent cloud services.
7. Attacker demands ransom or destroys the original key material to ensure the data remains permanently unrecoverable.

## Impact

Successful exploitation results in the immediate, widespread outage of services relying on the affected KMS keys. Depending on the data stored (e.g., S3 buckets, RDS snapshots, Secrets Manager), this leads to critical business disruption. If the adversary destroys the externally hosted key material, the data becomes unrecoverable, causing irreversible financial and operational damage.

## Recommendation

1. Deploy the suggested detection rule for 'DeleteImportedKeyMaterial' using AWS CloudTrail logs.
2. Configure AWS Organizations SCPs to strictly limit the principals authorized to perform 'kms:DeleteImportedKeyMaterial' and 'kms:ImportKeyMaterial'.
3. Monitor for unauthorized use of these KMS APIs, focusing on non-service principals and unexpected network sources.
4. Implement robust backup and secure storage procedures for all external key material (BYOK) used within the environment.
5. Perform an audit of KMS key policies to ensure the principle of least privilege is applied to destructive administrative actions.
