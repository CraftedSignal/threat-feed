---
title: AWS Bedrock GuardRails Deletion Attempt
slug: 2024-05-aws-bedrock-guardrails-deletion
description: Detection of attempts to delete AWS Bedrock GuardRails, security controls that prevent harmful AI outputs, via the DeleteGuardrail API in AWS CloudTrail logs, potentially indicating an adversary attempting to remove these safeguards after compromising credentials to manipulate model behavior for malicious purposes.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - bedrock
  - guardrails
  - defense-evasion
  - cloud
vendors:
  - AWS
products:
  - AWS Bedrock
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_DeleteGuardrail.html
  - https://attack.mitre.org/techniques/T1562/
rules:
  - title: AWS Bedrock GuardRail Deletion
    description: Detects attempts to delete AWS Bedrock GuardRails via the DeleteGuardrail API call in AWS CloudTrail logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudTrail Logging Disabled or Modified
    description: Detects attempts to disable or modify AWS CloudTrail logging configurations, which may indicate an attacker trying to evade detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief addresses the risk associated with the deletion of AWS Bedrock GuardRails. AWS Bedrock is a fully managed service that offers a choice of high-performing foundation models (FMs) from leading AI companies. GuardRails are security controls within Bedrock designed to prevent the generation of harmful, biased, or inappropriate content. This brief focuses on the detection of DeleteGuardrail API calls within AWS CloudTrail logs, as these actions could signify a malicious actor attempting to disable these safeguards. Monitoring for this activity is crucial as compromised credentials could allow adversaries to manipulate AI model outputs for malicious purposes, such as extracting sensitive information, generating offensive content, or bypassing security controls. The impact of successful GuardRail deletion can range from data leakage to the deployment of AI-driven attacks.

## Attack Chain

1. **Initial Access:** An attacker gains unauthorized access to an AWS account, potentially through compromised credentials obtained via phishing or credential stuffing.
2. **Privilege Escalation (if needed):** The attacker escalates privileges within the AWS account to gain the necessary permissions to manage Bedrock GuardRails.
3. **Discovery:** The attacker uses AWS CLI or the AWS Management Console to discover existing GuardRails within the Bedrock service.
4. **Disable Logging (optional):** The attacker attempts to disable or modify CloudTrail logging configurations to evade detection of their activities. This step may involve modifying CloudTrail settings via the AWS API or console.
5. **GuardRail Deletion:** The attacker calls the `DeleteGuardrail` API in the AWS Bedrock service, specifying the `guardrailIdentifier` of the GuardRail to be removed.
6. **Verify Deletion:** The attacker verifies the successful deletion of the GuardRail by checking the AWS Bedrock configuration.
7. **Malicious Model Interaction:** With the GuardRails removed, the attacker interacts with the Bedrock models to generate harmful or biased outputs, exfiltrate sensitive information, or perform other malicious activities.
8. **Lateral Movement/Exfiltration:** The attacker may use the generated content or exfiltrated data to further compromise the environment or achieve their objectives.

## Impact

The successful deletion of AWS Bedrock GuardRails can have significant consequences. If an attacker successfully removes these safeguards, they can manipulate AI model outputs to generate harmful or biased content, extract sensitive information, or bypass security controls designed to prevent prompt injection and other AI-specific attacks. The potential damage includes reputational damage, data breaches, and the deployment of AI-driven attacks, depending on the sensitivity of the data processed by the Bedrock models and the attacker's objectives. The number of affected users or systems can vary depending on the scope of the attacker's access and the criticality of the compromised AI models.

## Recommendation

*   Enable and monitor AWS CloudTrail logs for all AWS accounts, focusing on `bedrock.amazonaws.com` and `DeleteGuardrail` events to detect unauthorized GuardRail deletions.
*   Deploy the provided Sigma rule (`AWS Bedrock GuardRail Deletion`) to detect instances of the `DeleteGuardrail` API call within AWS CloudTrail logs.
*   Implement strict IAM policies with the principle of least privilege, limiting the users and roles that have permissions to modify or delete Bedrock GuardRails.
*   Establish an allowlist of expected administrators who regularly manage GuardRails configurations and adjust the Sigma rule (`AWS Bedrock GuardRail Deletion`) accordingly.
*   Monitor AWS Config for changes to CloudTrail configurations that could indicate attempts to disable or modify logging to evade detection.
