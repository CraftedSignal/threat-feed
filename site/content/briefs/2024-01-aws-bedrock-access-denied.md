---
title: AWS Bedrock Invoke Model Access Denied Attempt
slug: 2024-01-aws-bedrock-access-denied
description: Detection of AccessDenied errors when attempting to invoke AWS Bedrock models via the InvokeModel API indicates potential reconnaissance or privilege escalation attempts by an adversary with compromised credentials.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - bedrock
  - access-denied
  - privilege-escalation
vendors:
  - AWS
products:
  - AWS Bedrock
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Credentials
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_ListFoundationModels.html
  - https://trustoncloud.com/blog/exposing-the-weakness-how-we-identified-a-flaw-in-bedrocks-foundation-model-access-control/
  - https://attack.mitre.org/techniques/T1595/
rules:
  - title: AWS Bedrock InvokeModel Access Denied
    description: Detects AccessDenied errors when attempting to invoke AWS Bedrock models.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078
      - T1550
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Bedrock ListFoundationModels and InvokeModel Access Denied
    description: Detects a failed InvokeModel after a ListFoundationModels API call, indicating potential model access reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078
      - T1550
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on detecting unauthorized access attempts to AWS Bedrock models. The trigger is an `AccessDenied` error when a user or service attempts to invoke a Bedrock model using the `InvokeModel` API. The detection leverages AWS CloudTrail logs. This activity is concerning because it may signal an adversary attempting to access generative AI resources with compromised credentials but lacking the necessary permissions. Successful exploitation could lead to data exfiltration or manipulation of model outputs. The targeted resources are AWS Bedrock models, a suite of foundation models offered by Amazon.

## Attack Chain

1.  **Credential Compromise:** An attacker gains access to AWS credentials through phishing, credential stuffing, or other means (T1550).
2.  **Initial Access:** The attacker uses the compromised credentials to access the AWS environment (T1078).
3.  **Discovery: List Foundation Models:** The attacker attempts to list available Bedrock foundation models using the AWS CLI or API, potentially to identify accessible resources.
4.  **Attempt InvokeModel:** The attacker attempts to invoke a specific Bedrock model (e.g., `InvokeModel` API call) without proper permissions.
5.  **Access Denied:** AWS returns an `AccessDenied` error, logged in CloudTrail. This indicates insufficient permissions for the attempted action.
6.  **Privilege Escalation Attempt (Optional):** The attacker may attempt to escalate privileges by exploiting misconfigurations or vulnerabilities in IAM roles or policies.
7.  **Lateral Movement (Optional):** If privilege escalation is successful, the attacker may attempt to move laterally to other AWS resources.
8.  **Impact (Failed):** The attacker is unable to access or manipulate Bedrock models due to the `AccessDenied` error.

## Impact

While the `AccessDenied` error prevents immediate damage, the attempt itself indicates malicious activity. A successful privilege escalation following this access denial could lead to exfiltration of data used by the models, tampering with model outputs, or disruption of services relying on the Bedrock models. The TrustOnCloud reference highlights potential flaws in Bedrock's access control, emphasizing the need for monitoring.

## Recommendation

*   Deploy the "AWS Bedrock Invoke Model Access Denied" Sigma rule to your SIEM and tune for your environment to detect access denial attempts (rule provided below).
*   Investigate any detected instances of `AccessDenied` errors for `InvokeModel` API calls in CloudTrail logs, focusing on the source IP (`src`), user (`user`), and affected model (`requestParameters.modelId`).
*   Review and harden IAM policies related to AWS Bedrock to ensure least privilege access.
*   Enable and review CloudTrail logs for all AWS regions and services to ensure comprehensive security monitoring.
