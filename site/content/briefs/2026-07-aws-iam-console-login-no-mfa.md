---
title: AWS IAM User Console Login Without MFA
slug: 2026-07-aws-iam-console-login-no-mfa
description: This brief identifies successful logins to the AWS Management Console by standard IAM users without Multi-Factor Authentication (MFA). It focuses on the first observed occurrence within a 7-day history window for each user. An adversary who obtains a user's password can gain access if MFA is not enforced, representing a significant initial access vector. This event signals a critical posture gap that allows adversaries to achieve initial access using compromised credentials, leading to potential privilege escalation, data exfiltration, or resource deployment.
date: "2026-07-17T07:14:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - initial-access
  - aws
  - identity-and-access-management
  - mfa-bypass
vendors:
  - Amazon
products:
  - AWS Management Console
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An adversary who has phished, guessed, or otherwise obtained a user's password can sign in directly if MFA is not enforced for that user.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.initial-access.console-login-without-mfa/
rules:
  - title: AWS IAM User Console Login Without MFA
    description: Detects a standard AWS IAM user successfully logging into the AWS Management Console without Multi-Factor Authentication (MFA).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - cloud
      - aws
rules_count: 1
---

This brief describes the detection of a standard AWS Identity and Access Management (IAM) user successfully signing in to the AWS Management Console without Multi-Factor Authentication (MFA). This detection, a "New Terms" rule, fires only on the first observed occurrence within a configured 7-day history window for a given user. The absence of MFA significantly weakens security controls, as a username and password can be relatively easy for an adversary to obtain through methods such as phishing, credential stuffing, or password reuse. If MFA is not enforced, an attacker with compromised credentials can directly access the AWS environment. This detection is crucial for identifying posture gaps in an organization's cloud security, which, if left unaddressed, could lead to unauthorized initial access to critical cloud resources, potentially enabling further malicious activities like privilege escalation, data exfiltration, or deployment of rogue infrastructure. This rule specifically targets standard IAM users and excludes AWS root users and federated/SSO sign-ins, which have different MFA considerations.

## Attack Chain

1. **Initial Access - Credential Acquisition**: An adversary obtains valid AWS IAM user credentials (username and password) through various means, such as phishing campaigns targeting AWS users, credential stuffing attacks leveraging leaked credentials from other breaches, or brute-force password guessing.
2. **Authentication Attempt**: The adversary attempts to sign in to the AWS Management Console using the compromised IAM user credentials.
3. **Bypass Defense - Lack of MFA**: Due to the absence of enforced Multi-Factor Authentication for the targeted IAM user account, the AWS authentication process completes successfully with only the username and password.
4. **Initial Foothold**: The adversary gains unauthorized initial access to the AWS environment via the Management Console, bypassing a critical security layer.
5. **Post-Login Activity**: Upon gaining access, the adversary can explore the environment, escalate privileges, exfiltrate sensitive data, deploy malicious resources, or disrupt services, depending on the compromised user's permissions.

## Impact

A successful login without MFA grants an adversary initial access to an organization's AWS environment, immediately exposing cloud resources to potential compromise. This can lead to unauthorized data access and exfiltration, resource manipulation, privilege escalation, and even complete control over the compromised AWS account. While this detection primarily signals a critical security posture gap rather than an immediate breach, neglecting to enforce MFA significantly increases the attack surface. Organizations without universal MFA enforcement will regularly see this event, indicating a systemic vulnerability that attackers can exploit at any time. The impact can range from minor data exposure to major financial losses and reputational damage, depending on the permissions of the compromised IAM user and the attacker's subsequent actions.

## Recommendation

* Deploy the Sigma rule "AWS IAM User Console Login Without MFA" to your SIEM and tune for your environment to detect new occurrences.
* Investigate detected `aws.cloudtrail` events where `additionalEventData.MFAUsed` is "No" by reviewing the `source.ip`, `source.geo.country_name`, and `user_agent.original` fields for anomalies relative to the user's normal sign-in patterns.
* Correlate alerts from the Sigma rule with recent credential exposure alerts (e.g., password resets, phishing reports) involving the identified `user.name`.
* Enforce MFA for all IAM users capable of console access immediately using IAM policy conditions (`aws:MultiFactorAuthPresent`) or an Organizational Service Control Policy (SCP) to remediate the posture gap highlighted by the Sigma rule.
* For any `user.name` identified by this detection, force a password reset and review recent console/API activity for the account to identify potential post-login malicious actions.
* Consider migrating console access for users to federated/SSO sign-in with Identity Provider (IdP)-enforced MFA, which offers a more robust MFA solution than IAM user passwords.
