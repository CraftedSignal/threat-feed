---
title: AWS IAM CompromisedKeyQuarantine Policy Attachment
slug: 2024-07-aws-compromised-key-quarantine
description: Detection of the AWS `CompromisedKeyQuarantine` policy being attached to an IAM user, indicating that AWS has flagged the user's credentials as compromised or publicly exposed, and is providing instructions via a support case for remediation.
date: "2024-07-20T16:27:52Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - AWS
tags:
  - credential-access
  - cloud
  - aws
vendors:
  - AWS
products:
  - AWS Identity and Access Management (IAM)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_iam_compromisedkeyquarantine_policy_attached_to_user.toml
  - https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantine.html/
  - https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV2.html/
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
  - https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html
rules:
  - title: AWS IAM CompromisedKeyQuarantine Policy Attached to User
    description: Detects when the CompromisedKeyQuarantine policy is attached to an IAM user.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1078
      - T1078.004
      - T1552
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM AttachUserPolicy Event
    description: Detects any usage of the AttachUserPolicy API call to monitor IAM permissions changes.
    platform: sigma
    severity: informational
    tactics:
      - credential_access
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when the AWS-managed `CompromisedKeyQuarantine` or `CompromisedKeyQuarantineV2` policy is attached to an IAM user. This action is performed by AWS in response to identifying compromised or publicly exposed credentials associated with that user. The attachment of this policy restricts the user's ability to perform certain actions within the AWS environment. AWS typically accompanies this action with a support case that provides specific instructions for remediating the compromised credentials and restoring normal access. The rule is designed to alert security teams to this AWS-initiated quarantine so that they can investigate the root cause of the credential compromise and follow AWS's recommended remediation steps. This activity is flagged as high severity because it confirms active credential compromise impacting the cloud environment.

## Attack Chain

1.  **Credential Exposure:** An IAM user's credentials (access key ID and secret access key) are exposed publicly, e.g., through a code repository, public forum, or misconfigured system.
2.  **AWS Detection:** AWS detects the exposed credentials through its monitoring systems.
3.  **Policy Attachment:** AWS uses the `AttachUserPolicy` API operation to attach the `CompromisedKeyQuarantine` or `CompromisedKeyQuarantineV2` AWS managed policy to the affected IAM user. This policy restricts the user's permissions.
4.  **Support Case Creation:** AWS creates a support case detailing the compromised credentials and providing instructions for remediation.
5.  **Notification:** The AWS account owner is notified of the support case and the attached quarantine policy.
6.  **Investigation:** The security team investigates the root cause of the credential exposure.
7.  **Remediation:** Following the instructions in the support case, the security team disables or rotates the compromised credentials.
8.  **Policy Removal:** After the compromised credentials have been addressed, the security team detaches the quarantine policy.

## Impact

The attachment of the `CompromisedKeyQuarantine` policy by AWS indicates a significant security event. The user's access to AWS resources is immediately restricted, potentially disrupting legitimate operations. While AWS initiates this quarantine to prevent further damage, the underlying credential compromise could have allowed unauthorized access to sensitive data or resources prior to the quarantine. Successful exploitation prior to detection and remediation could lead to data breaches, resource hijacking, or other malicious activities. The number of affected users and the extent of the potential damage depend on the scope of access granted to the compromised IAM user.

## Recommendation

*   Deploy the provided Sigma rule to detect the attachment of the `CompromisedKeyQuarantine` policy via the `AttachUserPolicy` API call in CloudTrail logs to quickly identify compromised IAM user accounts.
*   Review the `aws.cloudtrail.request_parameters` field in the CloudTrail logs to identify the specific `userName` that has been quarantined (as referenced in the "Investigating AWS IAM CompromisedKeyQuarantine Policy Attached to User" section) and correlate with any AWS support cases.
*   Follow the instructions provided in the AWS support case, prioritizing credential rotation or revocation to prevent further unauthorized access.
*   Review and update policies on credential storage to prevent public exposure, as highlighted in the "Policy Update" remediation step, referencing the AWS IAM User Guide.
