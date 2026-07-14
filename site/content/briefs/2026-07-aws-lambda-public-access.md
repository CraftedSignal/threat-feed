---
title: AWS Lambda Function URL Created with Public Access
slug: 2026-07-aws-lambda-public-access
description: Adversaries can establish persistent, internet-accessible footholds within AWS environments by configuring AWS Lambda function URLs with an authentication type of NONE, allowing unauthenticated invocation directly from the public internet for command and control, data exfiltration, or on-demand code execution.
date: "2026-07-14T07:16:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - aws-lambda
  - threat-detection
  - persistence
  - defense-evasion
vendors:
  - Amazon Web Services
products:
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Adversaries can use a public function URL to establish a durable, internet-reachable entry point for command and control, data egress, or on-demand execution of attacker-controlled code, bypassing the need for valid AWS credentials to invoke the function.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Identifies the creation or update of an AWS Lambda function URL configured with an authentication type of NONE, which exposes the function to unauthenticated invocation directly from the public internet.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html
  - https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
rules:
  - title: AWS Lambda Function URL Created with Public Access
    description: Identifies the creation or update of an AWS Lambda function URL configured with an authentication type of NONE, which exposes the function to unauthenticated invocation directly from the public internet. This can be used for persistence, C2, or data exfiltration without valid AWS credentials.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1133
      - T1578
      - T1578.005
    data_sources:
      - cloud_audit
      - aws
rules_count: 1
---

Adversaries can establish persistent, internet-accessible footholds within AWS environments by configuring AWS Lambda function URLs with public access. This technique involves either creating new Lambda function URLs or modifying existing ones to have an authentication type of `NONE`. When set to `NONE`, the function becomes directly invokable from the public internet without requiring AWS authentication credentials. This misconfiguration allows attackers to establish a durable command and control (C2) channel, exfiltrate sensitive data, or execute arbitrary code on demand, bypassing typical AWS access controls. The threat leverages legitimate AWS functionality for malicious purposes, turning a service endpoint into an unauthenticated entry point. Such publicly exposed function URLs should be rare and are a strong indicator of potential malicious activity or significant misconfiguration warranting immediate review.

## Attack Chain

1. **Initial Access**: An adversary obtains valid AWS credentials (e.g., through phishing, compromised access keys, or exploiting another vulnerability) that possess permissions to manage AWS Lambda functions, specifically `lambda:CreateFunctionUrlConfig` or `lambda:UpdateFunctionUrlConfig`.
2. **Function Identification/Creation**: The attacker identifies an existing Lambda function within the compromised account or deploys a new, attacker-controlled Lambda function.
3. **Function URL Configuration**: Using the compromised credentials, the adversary executes the `CreateFunctionUrlConfig` or `UpdateFunctionUrlConfig` API call against the target Lambda function.
4. **Public Access Establishment**: During the function URL configuration, the attacker explicitly sets the `AuthType` parameter to `NONE`, making the function URL publicly accessible without any authentication.
5. **URL Retrieval**: The attacker captures the newly generated or modified public function URL from the API response or AWS console.
6. **Persistence and Exploitation**: The public function URL serves as a persistent, unauthenticated endpoint. The adversary can then invoke this URL directly from the internet to achieve command and control, exfiltrate data, or trigger further malicious code execution, bypassing the need for valid AWS credentials for subsequent interactions.

## Impact

Successful exploitation of this misconfiguration results in the creation of a persistent, unauthenticated access point to an AWS Lambda function. This allows adversaries to maintain a foothold within the targeted AWS environment, potentially facilitating long-term command and control operations, unauthenticated data exfiltration from resources accessible by the Lambda function's execution role, or on-demand execution of attacker-controlled code. While the direct number of victims is not specified, organizations utilizing AWS Lambda are susceptible if proper access controls are not enforced or if initial account compromise occurs. The primary damage is the circumvention of standard authentication mechanisms, increasing the attack surface and enabling further malicious activity within the cloud infrastructure.

## Recommendation

* Deploy the provided Sigma rule to your SIEM system to detect `CreateFunctionUrlConfig` and `UpdateFunctionUrlConfig` events where `authType` is set to `NONE` in your `aws.cloudtrail` logs.
* Upon detection of the `AWS Lambda Function URL Created with Public Access` event, immediately investigate the `aws.cloudtrail.user_identity.arn`, `source.ip`, and `user_agent.original` fields to identify the actor and source of the configuration change.
* Review the associated Lambda function (`functionName`) and its code for any signs of tampering or malicious modifications.
* Restrict `lambda:CreateFunctionUrlConfig` and `lambda:UpdateFunctionUrlConfig` permissions to only trusted roles and principals to limit the ability of compromised identities to establish public function URLs.
* If an unauthorized public function URL is discovered, change its authentication type to `AWS_IAM` or delete the function URL configuration entirely to revoke public access.
