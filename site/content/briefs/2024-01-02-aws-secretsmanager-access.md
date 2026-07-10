---
title: First Time Seen AWS Secret Value Accessed in Secrets Manager
slug: 2024-01-02-aws-secretsmanager-access
description: This rule detects the first time a specific user identity has programmatically retrieved a secret value from AWS Secrets Manager using the GetSecretValue action, which may indicate a compromised AWS service attempting to access secrets.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - credential-access
vendors:
  - AWS
products:
  - AWS Secrets Manager
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
  - https://detectioninthe.cloud/ttps/credential_access/access_secret_in_secrets_manager/
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_BatchGetSecretValue.html
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-secrets-manager-enum
  - https://attack.mitre.org/techniques/T1555/
  - https://attack.mitre.org/techniques/T1555/006/
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: Detect New Terms AWS Secret Value Accessed
    description: Detects the first time a specific user identity has programmatically retrieved a secret value from AWS Secrets Manager using the GetSecretValue action.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
      - T1555.006
    data_sources:
      - cloudtrail
      - aws
  - title: Detect SecretsManager BatchGetSecretValue Usage
    description: Detects use of the BatchGetSecretValue API in AWS SecretsManager, which can be used to enumerate secrets at scale.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1555
      - T1555.006
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the initial use of the AWS Secrets Manager's `GetSecretValue` API by a specific user identity within an AWS environment. The rule focuses on the scenario where a compromised AWS service, such as an EC2 instance or Lambda function, attempts to leverage its IAM role to access stored secrets. This activity is flagged when a user/account pair is observed utilizing `GetSecretValue` for the first time, suggesting potential unauthorized credential access. The rule applies to environments leveraging AWS Secrets Manager for credential storage and is intended to detect anomalous access patterns indicative of account compromise or privilege escalation. This detection does not focus on versioned secrets or batch retrieval via `BatchGetSecretValue`.

## Attack Chain

1. An attacker gains initial access to an AWS environment, possibly through compromising an EC2 instance or Lambda function.
2. The compromised service has an IAM role associated with it that grants permissions to interact with AWS Secrets Manager.
3. The attacker leverages the compromised service's IAM role to make API calls to Secrets Manager.
4. The attacker executes a `GetSecretValue` API call, targeting a specific secret within Secrets Manager.
5. AWS Secrets Manager authenticates the request based on the attached IAM role and its associated permissions.
6. If the IAM role has sufficient permissions, Secrets Manager retrieves the requested secret and returns it to the compromised service.
7. The attacker exfiltrates the retrieved secret for malicious purposes, such as lateral movement or data theft.

## Impact

A successful attack can lead to the exposure of sensitive credentials stored within AWS Secrets Manager, allowing attackers to gain unauthorized access to other AWS services or internal resources. This may result in data breaches, service disruptions, or financial losses. The severity depends on the permissions associated with the compromised IAM role and the value of the exposed secrets.

## Recommendation

*   Deploy the Sigma rule `Detect New Terms AWS Secret Value Accessed` to your SIEM and tune for your environment to detect anomalous access to secrets manager.
*   Review IAM permission policies for user identities and specific secrets accessed, following the least privilege principle as referenced in the investigation guide.
*   Investigate abnormal values in the `user_agent.original` field by comparing them with the intended and authorized usage and historical data, as suggested in the rule's triage steps.
*   Implement security best practices as [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
