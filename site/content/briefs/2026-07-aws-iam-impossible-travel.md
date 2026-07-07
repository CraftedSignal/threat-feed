---
title: AWS IAM User Console Login from Multiple Geolocations
slug: 2026-07-aws-iam-impossible-travel
description: Adversaries leverage adversary-in-the-middle (AiTM) phishing and session theft to compromise AWS IAM user credentials, leading to concurrent successful AWS Management Console logins from multiple distinct geographic locations, indicating account compromise and enabling unauthorized access to cloud resources despite MFA.
date: "2026-07-03T15:41:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - aws
  - initial-access
  - credential-access
  - aitm-phishing
  - session-theft
  - impossible-travel
vendors:
  - Amazon Web Services
products:
  - AWS Management Console
  - AWS IAM
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A single user authenticating from multiple geographic locations in a brief period indicates that the account's credentials or console session are being used from more than one place at once.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: A single user authenticating from multiple geographic locations in a brief period indicates that the account's credentials or console session are being used from more than one place at once. This is a hallmark of adversary-in-the-middle (AiTM) phishing and session theft, where the legitimate user signs in from their location while the attacker replays the captured session or credentials from their own infrastructure.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/initial_access_console_login_iam_user_multiple_geolocations.toml
  - https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-kit-and-beyond/
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html
---

Adversaries are actively employing adversary-in-the-middle (AiTM) phishing and session theft techniques to compromise AWS IAM user accounts. This threat is characterized by a single IAM user successfully authenticating to the AWS Management Console from two or more geographically distinct countries within a brief timeframe, a physically impossible scenario. This behavior is a strong indicator of compromise, even when multi-factor authentication (MFA) appears satisfied, as AiTM proxies effectively relay the live MFA challenge from the legitimate user to the AWS login page. The attacker then uses the captured session or credentials to log in from their own infrastructure, leading to the divergent geolocation pattern. This technique poses a significant risk to AWS environments by providing unauthorized access to cloud resources, potentially leading to data exfiltration, resource manipulation, or further lateral movement within the compromised cloud infrastructure. This detection mechanism serves as a crucial CloudTrail-native analog to identity-provider impossible-travel alerts.

## Attack Chain

1.  **Initial Access (Phishing)**: The adversary initiates a phishing campaign, often through highly convincing emails targeting AWS IAM users, to entice them to visit a malicious website controlled by the attacker.
2.  **AiTM Infrastructure Deployment**: The attacker sets up an adversary-in-the-middle (AiTM) proxy server, which acts as an intermediary between the victim's browser and the legitimate AWS Management Console login page.
3.  **Credential and Session Theft**: When the victim attempts to log into AWS through the phishing site, the AiTM proxy relays their entered credentials (username, password) and any MFA responses to the legitimate AWS login page. Simultaneously, the proxy captures the session cookies returned by AWS.
4.  **Concurrent Session Establishment**: As the legitimate user successfully logs in from their actual geographic location, the attacker immediately uses the captured session cookies or credentials to establish a separate, concurrent login session to the AWS Management Console from their own geographically distinct infrastructure.
5.  **Persistence and Privilege Escalation**: Once inside, the attacker may modify the compromised IAM user's policies, create new access keys (`CreateAccessKey`), or alter login profiles to maintain persistence and potentially elevate privileges within the AWS environment.
6.  **Impact (Data Exfiltration / Resource Manipulation)**: The attacker then leverages the unauthorized access to exfiltrate sensitive data from S3 buckets, deploy unauthorized compute resources (e.g., EC2 instances for cryptocurrency mining), or disrupt critical cloud services.

## Impact

A successful AiTM attack leading to impossible travel on AWS can result in severe consequences. Attackers gain full control over the compromised IAM user's permissions, enabling actions such as creating new access keys, modifying existing user policies to grant broader access, or even altering MFA configurations. This unauthorized access allows for direct data exfiltration from services like S3, deployment of malicious resources for illicit activities (e.g., launching EC2 instances for botnets or crypto mining), and disruption of business-critical cloud infrastructure. The ability to bypass MFA by relaying challenges makes this a particularly insidious threat, leading to significant financial loss, reputational damage, and potential compliance violations for affected organizations.

## Recommendation

*   Deploy the detection logic described in this brief to your SIEM, leveraging `AWS CloudTrail` logs for `signin.amazonaws.com` events.
*   Review detections for `Esql.source_geo_country_iso_code_values` and `Esql.source_ip_values` to identify the origin of suspicious logins and verify against expected user activity.
*   Investigate `aws.cloudtrail.user_identity.arn` for any suspicious hands-on-keyboard activities immediately following impossible travel alerts, such as `CreateAccessKey` events, changes to login profiles, or IAM policy modifications.
*   For confirmed compromises, revoke the affected user's console sessions, force a password reset, rotate access keys, and reconfigure MFA.
*   Migrate AWS Management Console access to AWS IAM Identity Center and enforce phishing-resistant MFA methods, such as FIDO2 security keys or passkeys, which are highly effective against AiTM relay attacks.
