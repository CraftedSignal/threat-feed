---
title: AWS Systems Manager SecureString Parameter Request with Decryption Flag
slug: 2024-05-aws-ssm-securestring-access
description: This rule detects when an AWS resource accesses SecureString parameters within AWS Systems Manager (SSM) with the decryption flag set to true, potentially indicating credential access.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - credential-access
  - cloud
vendors:
  - AWS
products:
  - AWS Systems Manager
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://docs.aws.amazon.com/vsts/latest/userguide/systemsmanager-getparameter.html
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html
  - https://attack.mitre.org/techniques/T1555/
  - https://attack.mitre.org/techniques/T1555/006/
rules:
  - title: AWS SSM SecureString Parameter Request with Decryption Flag
    description: Detects an AWS identity accessing SecureString parameters in SSM with the withDecryption flag set to true.
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
  - title: AWS SSM GetParameter without Encryption in transit flag
    description: Detects when AWS SSM GetParameter action is done without encryption in transit
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when an AWS resource interacts with AWS Systems Manager (SSM) SecureString parameters and requests decryption. SecureStrings, encrypted using KMS keys, protect sensitive information like encryption keys, passwords, and credentials. An adversary gaining unauthorized access and decrypting these strings could bypass security controls and expose plaintext values for immediate misuse or exfiltration. The rule focuses on `GetParameter` or `GetParameters` API actions, specifically when the `withDecryption` parameter is set to true. This activity could signal a broader attack involving privilege escalation or lateral movement. The rule aims to detect the initial occurrence of such access, providing early warning of potential credential compromise. This detection rule was last updated on 2026-04-10.

## Attack Chain

1. An attacker gains initial access to an AWS environment through compromised credentials or a misconfigured IAM role (TA0001).
2. The attacker attempts to discover sensitive information stored as SecureString parameters within AWS Systems Manager (SSM) (T1555).
3. The attacker uses the AWS CLI or SDK to call the `GetParameter` or `GetParameters` API actions targeting specific SecureString parameters.
4. The attacker sets the `withDecryption` parameter to true in the API request, indicating a desire to retrieve the plaintext value of the SecureString.
5. The AWS SSM service processes the request and decrypts the SecureString using the appropriate KMS key.
6. The decrypted value is returned to the attacker as part of the API response.
7. The attacker uses the retrieved credentials or sensitive information for unauthorized activities, such as lateral movement, data exfiltration, or resource manipulation (TA0006).
8. The attacker may attempt to further obfuscate their actions by deleting CloudTrail logs or modifying SSM parameter access policies (TA0005).

## Impact

Successful exploitation could lead to the exposure of sensitive credentials, including passwords, API keys, and database connection strings. This would allow an attacker to escalate privileges, move laterally within the AWS environment, and potentially gain access to critical systems and data. The impact ranges from data breaches and service disruption to complete compromise of the AWS account. The risk score associated with this behavior is 47, indicating a significant potential for damage.

## Recommendation

*   Deploy the Sigma rule "AWS SSM SecureString Parameter Request with Decryption Flag" to your SIEM and tune for your environment to detect suspicious decryption requests of SecureStrings.
*   Enable AWS CloudTrail logs and configure the AWS integration to ingest them into your SIEM to provide the necessary data source for the Sigma rule above.
*   Enable event logging for AWS Systems Manager (SSM) API actions within CloudTrail's data events settings to ensure comprehensive coverage.
*   Review and revise IAM permissions to adhere to the principle of least privilege, restricting access to SSM parameters only to authorized users and roles (reference the "Possible Investigation Steps" in the content section).
*   Audit SSM parameter access policies to ensure they are strict and that logging is enabled to track access with decryption (reference the "Audit Parameter Access Policies" section).
