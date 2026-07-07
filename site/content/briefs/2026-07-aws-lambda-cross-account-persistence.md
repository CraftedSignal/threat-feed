---
title: AWS Lambda Function Policy Updated to Allow Cross-Account Invocation
slug: 2026-07-aws-lambda-cross-account-persistence
description: An adversary can establish persistence and defense evasion by modifying an AWS Lambda function's resource policy via the `AddPermission` API to grant `lambda:InvokeFunction` permissions to a principal in an external AWS account, enabling unauthorized function invocation and potential data exfiltration without altering function code.
date: "2026-07-03T16:14:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - persistence
  - defense-evasion
vendors:
  - AWS
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Using AddPermission, an adversary can authorize a principal in another account to call a function, creating a cross-account backdoor for execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Using AddPermission, an adversary can authorize a principal in another account to call a function, creating a cross-account backdoor for execution or for relaying data to attacker-controlled infrastructure without modifying the function's code.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html
  - https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html
rules:
  - title: AWS Lambda Function Policy Updated to Allow Cross-Account Invocation
    description: Identifies a change to an AWS Lambda function resource policy that grants invoke permissions to an AWS account principal in an external account, indicating a potential persistence backdoor. Excludes public grants ('*') and AWS service principals.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1546
      - T1578
      - T1578.005
    data_sources:
      - cloud_service
      - aws
      - cloudtrail
rules_count: 1
---

This threat involves an adversary establishing a cross-account persistence mechanism within Amazon Web Services (AWS) by manipulating AWS Lambda function resource policies. Following an initial compromise of an AWS identity, the attacker uses the `AddPermission` API to grant `lambda:InvokeFunction` access to a principal in an external, attacker-controlled AWS account. This action creates a backdoor, allowing the adversary to invoke the targeted Lambda function at will or relay its output to their infrastructure, all without modifying the function's underlying code, which might be more closely monitored by defenders. This technique, identified as a high-severity concern, bypasses typical code-level scrutiny and enables sustained access or data exfiltration, highlighting the importance of monitoring policy changes on critical cloud resources.

## Attack Chain

1.  An adversary successfully compromises an AWS identity (e.g., an IAM user, role, or access key) with permissions to modify AWS Lambda function policies within a target AWS account.
2.  Using the compromised credentials, the adversary authenticates to the target AWS environment and identifies a Lambda function to backdoor, often one with access to sensitive data or critical operations.
3.  The adversary invokes the `lambda:AddPermission` API call, specifying the target Lambda function and a new policy `Statement` in the request parameters.
4.  This `Statement` explicitly grants `lambda:InvokeFunction` access to an AWS principal (user or role) located in an AWS account controlled by the adversary.
5.  The successful `AddPermission` operation establishes a new, unauthorized cross-account invocation path to the Lambda function.
6.  From their own AWS account, the adversary can now invoke the compromised Lambda function, executing its code and potentially accessing or exfiltrating sensitive data that the function is authorized to process.
7.  This action provides persistent access to the function's capabilities, allowing for ongoing data collection, further reconnaissance, or execution of malicious logic within the victim's environment.

## Impact

The successful exploitation of this persistence mechanism can lead to severe consequences, including unauthorized execution of code, data exfiltration, and sustained access to the victim's AWS environment. By invoking a backdoored Lambda function, an attacker can bypass traditional security controls that monitor code changes or direct access attempts. If the compromised Lambda function processes sensitive customer data, intellectual property, or financial information, this could result in significant data breaches, regulatory non-compliance fines, reputational damage, and financial losses. The attack grants an attacker a covert method to maintain control and leverage existing trusted resources within the target's cloud infrastructure.

## Recommendation

*   Deploy the Sigma rule "AWS Lambda Function Policy Updated to Allow Cross-Account Invocation" to your SIEM and tune for your environment by validating known legitimate cross-account grants.
*   Regularly review `aws.cloudtrail.request_parameters` logs for `AddPermission` API calls to identify unusual or unauthorized principals, especially those from external AWS accounts.
*   Restrict `lambda:AddPermission` permissions to a very small set of highly trusted IAM roles and principles in your AWS accounts.
*   Investigate `aws.cloudtrail.user_identity.arn`, `source.ip`, and `user_agent.original` for any alerts generated by the rule to understand the actor and origin of the policy change.
