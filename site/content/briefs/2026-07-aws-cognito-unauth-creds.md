---
title: AWS Cognito Unauthenticated Identity Pool Credentials Issued
slug: 2026-07-aws-cognito-unauth-creds
description: This threat involves adversaries obtaining temporary AWS credentials from a misconfigured Cognito Identity Pool without authentication. If a Cognito Identity Pool is set to allow unauthenticated (guest) access and its associated unauthenticated IAM role has overly broad permissions, attackers can discover the pool ID, call `GetId`, and then `GetCredentialsForIdentity` to acquire AWS credentials. This grants them unauthorized access to AWS resources and sensitive data, bypassing typical authentication mechanisms.
date: "2026-07-17T08:29:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - cognito
  - misconfiguration
  - credential-access
  - cloud-security
vendors:
  - Amazon Web Services
products:
  - Cognito Identity Pools
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Adversaries who discover an identity pool ID can call GetId followed by GetCredentialsForIdentity with no login token at all to obtain temporary credentials.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A pool that grants those anonymous identities meaningful IAM permissions becomes a public, unauthenticated path to real AWS credentials.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pool-roles.html
  - https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html
  - https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/
  - https://github.com/RhinoSecurityLabs/pacu/tree/master/pacu/modules/cognito__attack
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_cognito_unauthenticated_identity_pool_credentials_issued.toml
rules:
  - title: Detect AWS Cognito Unauthenticated Identity Pool Credentials Issued
    description: Detects successful issuance of temporary AWS credentials from a Cognito Identity Pool to an unauthenticated identity (type 'Unknown'), indicating potential misconfiguration exploitation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1078
      - T1078.004
      - T1552
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

Adversaries are targeting misconfigured AWS Cognito Identity Pools to obtain temporary AWS credentials without authentication. This specific threat leverages a design feature intended for legitimate anonymous app access, `AllowUnauthenticatedIdentities`, which, when combined with an overpermissioned unauthenticated IAM role, creates a significant security vulnerability. Attackers discover Cognito Identity Pool IDs, often exposed in public resources like mobile app binaries or web application JavaScript, and then programmatically request guest identities and subsequent temporary AWS credentials using API calls such as `GetId` and `GetCredentialsForIdentity`. If successful, these credentials grant unauthorized access to AWS resources, bypassing standard authentication mechanisms. This misconfiguration is critical because it provides a public, unauthenticated pathway to real AWS credentials, allowing adversaries to access sensitive data or manipulate cloud infrastructure. This Elastic detection rule focuses on identifying the initial issuance of such unauthenticated credentials from a previously unobserved Cognito Identity Pool, flagging potential exploitation.

## Attack Chain

1. **Reconnaissance & Discovery**: An adversary identifies a target AWS Cognito Identity Pool ID. This ID is often exposed in publicly accessible client-side code, such as mobile application binaries, web application JavaScript files, or inadvertently committed to public source code repositories.
2. **Initial Guest Identity Acquisition**: The adversary makes an unauthenticated API call to `cognito-identity.amazonaws.com`'s `GetId` endpoint, passing the discovered Identity Pool ID to obtain a unique guest identity.
3. **Temporary Credential Request**: With the guest identity in hand, the adversary then makes a subsequent unauthenticated API call to the `GetCredentialsForIdentity` endpoint, providing the guest identity.
4. **Credential Issuance**: If the Cognito Identity Pool is configured with `AllowUnauthenticatedIdentities` enabled and has an associated unauthenticated IAM role, the AWS service successfully issues temporary AWS access keys, secret keys, and a session token to the adversary.
5. **AWS API Access**: The adversary uses these newly acquired temporary AWS credentials to authenticate and make further API calls to other AWS services, such as S3, EC2, or IAM.
6. **Privilege Escalation / Data Exfiltration**: Depending on the permissions granted to the Cognito Identity Pool's unauthenticated IAM role, the adversary may gain unauthorized access to sensitive data (e.g., S3 buckets), manipulate cloud resources (e.g., launch EC2 instances), or even attempt further privilege escalation within the AWS environment.
7. **Impact**: This unauthenticated access can lead to data exfiltration, service disruption, resource hijacking, or the establishment of persistent backdoors, ultimately compromising the confidentiality, integrity, or availability of the AWS cloud environment.

## Impact

A successful exploitation of a misconfigured AWS Cognito Identity Pool can lead to severe consequences. Attackers gain unauthorized and unauthenticated access to AWS resources, potentially enabling data exfiltration from storage services like S3, unauthorized modifications to cloud infrastructure, or the deployment of malicious resources. The impact is particularly high when the unauthenticated IAM role is excessively permissive, allowing broad control over the AWS account. This misconfiguration creates a direct, public pathway for adversaries to obtain legitimate AWS credentials, bypassing traditional authentication and authorization controls, and placing the entire affected AWS environment at risk of compromise, including financial impact from resource abuse or regulatory penalties from data breaches.

## Recommendation

* Enable AWS CloudTrail data events for `AWS::Cognito::IdentityPool` resources, specifically capturing `GetCredentialsForIdentity`, `GetId`, `GetOpenIdToken`, `GetOpenIdTokenForDeveloperIdentity`, and `UnlinkIdentity` actions.
* Deploy the "Detect AWS Cognito Unauthenticated Identity Pool Credentials Issued" Sigma rule to your SIEM to alert on the initial occurrence of unauthenticated credential issuance.
* Review the IAM policies attached to unauthenticated roles of all Cognito Identity Pools; ensure they adhere to the principle of least privilege, granting only the absolute minimum permissions required for legitimate anonymous use.
* If unauthenticated access is not required for an Identity Pool, immediately disable the `AllowUnauthenticatedIdentities` setting within its configuration.
* For any alerts from the Sigma rule, investigate the `source.ip`, `user_agent.original`, and `source.geo` fields in CloudTrail logs to determine the origin of the `GetCredentialsForIdentity` call and search for subsequent API calls made with the obtained credentials.
