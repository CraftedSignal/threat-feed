---
title: Potential Abuse of AWS Console GetSigninToken
slug: 2024-04-aws-get-signin-token-abuse
description: Adversaries may abuse the AWS GetSigninToken API to create temporary federated credentials for obfuscating compromised AWS access keys and pivoting to console sessions without MFA, potentially leading to lateral movement within the AWS environment.
date: "2024-04-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - aws
  - cloud
  - lateral-movement
  - credential-access
vendors:
  - Amazon
products:
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/NetSPI/aws_consoler
  - https://www.crowdstrike.com/blog/analysis-of-intrusion-campaign-targeting-telecom-and-bpo-companies/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_console_getsignintoken.yml
rules:
  - title: AWS Console GetSigninToken Potential Abuse
    description: Detects potentially suspicious events involving GetSigninToken API calls, which may indicate credential abuse or lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral-movement
    techniques:
      - T1021.007
      - T1550.001
    data_sources:
      - aws
      - cloudtrail
  - title: AWS Console GetSigninToken Called by Uncommon User Agent
    description: Detects GetSigninToken calls using a user agent string that is not commonly associated with legitimate AWS console access.
    platform: sigma
    severity: low
    tactics:
      - lateral-movement
    techniques:
      - T1021.007
      - T1550.001
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

The AWS GetSigninToken API, typically used for legitimate console access, can be abused by attackers to generate temporary, federated credentials. This technique, often facilitated by tools like `aws_consoler`, allows attackers to obfuscate the compromised access keys used to generate the tokens. By pivoting from the AWS CLI to console sessions with these temporary credentials, adversaries bypass MFA requirements and complicate forensic investigations. This activity is crucial for defenders to monitor, especially in environments not configured for AWS SSO, as it can indicate unauthorized access and lateral movement within the AWS infrastructure. The tool `aws_consoler` is specifically designed to automate this process, creating a streamlined path for malicious actors to leverage compromised credentials for further exploitation.

## Attack Chain

1.  An attacker gains initial access to AWS environment using compromised credentials (access key, secret key).
2.  The attacker uses the compromised credentials with the AWS CLI or SDK to call the `GetSigninToken` API.
3.  AWS CloudTrail logs the `GetSigninToken` event with the event source `signin.amazonaws.com` and event name `GetSigninToken`.
4.  The `GetSigninToken` API returns a temporary sign-in token.
5.  The attacker uses the temporary token along with the AWS account ID to construct a sign-in URL.
6.  The attacker accesses the AWS Management Console via the crafted URL, bypassing MFA if the original compromised credentials required it.
7.  Once in the console, the attacker performs reconnaissance, identifies valuable resources, and escalates privileges as needed.
8.  The attacker moves laterally within the AWS environment, accessing and potentially exfiltrating sensitive data, or disrupting services.

## Impact

Successful abuse of the `GetSigninToken` API can lead to unauthorized access to the AWS Management Console, enabling lateral movement and data exfiltration.  The obfuscation of the original compromised credentials makes incident response more difficult. While the exact number of victims is unknown, this technique has been observed in intrusions targeting telecom and BPO companies.  The impact includes potential data breaches, service disruptions, and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious `GetSigninToken` events in AWS CloudTrail logs.
*   Investigate any `GetSigninToken` events originating from outside of expected AWS SSO user agents or other known legitimate sources.
*   Monitor AWS CloudTrail logs for `GetSigninToken` events where the requesting user identity does not match expected patterns.
*   Implement and enforce MFA for all AWS IAM users, even though this attack bypasses it for console access using the temporary tokens.
*   Review and restrict IAM policies to adhere to the principle of least privilege, minimizing the potential impact of compromised credentials.
