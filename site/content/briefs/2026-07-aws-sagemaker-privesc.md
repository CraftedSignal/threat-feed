---
title: AWS SageMaker Execution Role Privilege Escalation via PassRole
slug: 2026-07-aws-sagemaker-privesc
description: An adversary with SageMaker resource-creation rights and broad iam:PassRole permissions can escalate privileges by passing highly privileged IAM roles to SageMaker notebook instances, training, processing, or pipeline jobs.
date: "2026-07-31T09:23:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - privilege-escalation
  - sagemaker
vendors:
  - Amazon
products:
  - AWS SageMaker
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An adversary holding both SageMaker create permissions and a broad iam:PassRole grant can pass a more privileged role to a resource they control and execute code as that role, escalating privileges.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-roles.html
  - https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_CreateNotebookInstance.html
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.execution.sagemaker-update-lifecycle-config/
---

Adversaries targeting AWS environments can leverage Amazon SageMaker to escalate privileges by exploiting the interaction between SageMaker resource creation actions and IAM role assignment. When creating resources like Notebook Instances, Training Jobs, Processing Jobs, AutoML Jobs, or Pipelines, a caller must possess the `iam:PassRole` permission to associate an execution role with the new resource. 

If an attacker has sufficient permissions to initiate these SageMaker resources and holds a broad `iam:PassRole` grant, they can pass a more privileged role - or a role from a different account - to the resource. The resulting SageMaker resource then executes code under the context of the assigned role, effectively allowing the attacker to perform actions that the original caller could not. This technique is particularly dangerous as it utilizes legitimate, expected functionality to bridge security boundaries. Monitoring for unusual associations between IAM principals and execution roles is essential for detecting potential credential abuse or unauthorized privilege escalation within AWS MLOps workflows.

## Impact

Successful exploitation allows an attacker to achieve code execution as a more privileged IAM role, leading to unauthorized data access, persistence, or broader administrative control within the AWS account. This risk is especially critical in production MLOps environments where high-privilege service roles are frequently utilized for legitimate automated data processing.

## Recommendation

- Implement the detection logic to identify the first time an IAM principal uses a specific `roleArn` for SageMaker resource creation within a 7-day window.
- Review the `aws.cloudtrail.user_identity.arn` of the principal performing the action and investigate the `roleArn` passed in `aws.cloudtrail.request_parameters` for unauthorized privilege escalation.
- Constrain `iam:PassRole` permissions using IAM policy conditions (such as `iam:PassedToService`) to ensure that principals can only pass narrowly scoped, approved execution roles to SageMaker.
- Rotate or restrict credentials for any principal identified using an unexpected or overly privileged execution role.
