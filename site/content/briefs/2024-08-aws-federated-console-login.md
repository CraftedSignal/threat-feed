---
title: AWS Federated User Console Login without MFA Enforcement
slug: 2024-08-aws-federated-console-login
description: Detection of successful AWS Management Console logins by federated users, which pose a security risk due to potential lack of enforced MFA as CloudTrail does not reliably record MFA status for federated users.
date: "2024-08-19T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloudtrail
  - federated-user
  - initial-access
vendors:
  - Amazon
products:
  - Amazon Web Services
  - AWS Management Console
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://hackingthe.cloud/aws/post_exploitation/create_a_console_session_from_iam_credentials/
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/techniques/T1078/004/
  - https://attack.mitre.org/tactics/TA0001/
rules:
  - title: AWS Federated User Console Login
    description: Detects successful AWS Management Console logins by federated users based on CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS GetSigninToken from Unfamiliar Source
    description: Detects GetSigninToken API calls originating from unusual IP addresses, ASNs or user agents.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when a federated user successfully logs into the AWS Management Console. Federated users are granted temporary credentials to access AWS resources. A potential security risk arises if MFA is not enforced, as adversaries might exploit stolen or misconfigured credentials to gain unauthorized access. CloudTrail alone cannot reliably indicate MFA usage for federated logins. The rule increases priority if a related 'GetSigninToken' event has a different source IP, ASN, geo, or user-agent from the subsequent 'ConsoleLogin', suggesting possible token relay or abuse. This alert requires correlation with Identity Provider (IdP) authentication logs to confirm MFA enforcement for the session. This detection is crucial for organizations relying on federated access for AWS resources, as it helps identify potentially compromised accounts or misconfigured access policies.

## Attack Chain

1. An attacker obtains valid credentials for a federated user, potentially through phishing, credential stuffing, or insider threat.
2. The attacker leverages the stolen credentials to request a sign-in token using `GetSigninToken` from `signin.amazonaws.com`.
3. The attacker initiates a `ConsoleLogin` event to the AWS Management Console using the obtained sign-in token.
4. The `ConsoleLogin` event is recorded in AWS CloudTrail with `aws.cloudtrail.user_identity.type` as "FederatedUser" and `event.outcome` as "success".
5. Defenders observe the `ConsoleLogin` event and correlate it with IdP logs to ascertain if MFA was enforced during authentication.
6. If MFA was not enforced and the source IP/ASN/geo are suspicious, the attacker proceeds to perform unauthorized actions within the AWS environment.
7. The attacker may attempt lateral movement or privilege escalation using the federated user's granted permissions.
8. The attacker achieves their objective, such as data exfiltration, resource destruction, or deploying malicious infrastructure.

## Impact

A successful attack can lead to unauthorized access to sensitive data, compromise of critical infrastructure, and potential financial losses. The severity depends on the permissions granted to the compromised federated user. Organizations in all sectors using AWS federated access are at risk. Without proper MFA enforcement, the likelihood of successful exploitation significantly increases. Failure to detect and respond to such incidents can result in compliance violations and reputational damage.

## Recommendation

*   Deploy the following Sigma rule to detect successful AWS Management Console logins by federated users (see 'AWS Federated User Console Login' Sigma rule).
*   Correlate identified `ConsoleLogin` events with Identity Provider (IdP) logs to verify MFA enforcement, focusing on discrepancies in source IP, ASN, geo, or user-agent between 'GetSigninToken' and 'ConsoleLogin' events.
*   Implement or enforce multi-factor authentication (MFA) for all federated user accounts to enhance security and prevent similar incidents in the future.
*   Review and update IAM policies and roles associated with federated users to ensure they follow the principle of least privilege.
*   Maintain allow-lists for corp/VPN CIDRs, approved ASNs, and known automation user-agents to reduce false positives.
