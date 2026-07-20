---
title: AWS IAM Session Token Used from Multiple Addresses
slug: 2026-07-aws-iam-session-token-multiple-addresses
description: This threat brief describes a detection for suspicious activity where an AWS IAM user's temporary session token is accessed from multiple distinct IP addresses, networks, cities, and user agents within a short timeframe, indicating potentially compromised credentials used for initial access and resource manipulation.
date: "2026-07-20T13:10:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - initial-access
  - identity-and-access-audit
vendors:
  - Amazon
products:
  - AWS IAM
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This rule identifies potentially suspicious activity by detecting instances where a single IAM user's temporary session token is accessed from multiple IP addresses within a short time frame. Such behavior may suggest that an adversary has compromised temporary credentials and is utilizing them from various locations.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/initial_access_iam_session_token_used_from_multiple_addresses.toml
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html
  - https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html
  - https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/
---

This brief details a detection strategy for identifying the misuse of compromised temporary AWS IAM user session tokens. Adversaries, after obtaining legitimate temporary credentials, often attempt to utilize them from various geographic locations and different technical environments to evade detection. This activity typically occurs rapidly after initial access is gained to a user's system where these tokens reside. The detection identifies instances where a single IAM user's temporary session token is accessed from at least two distinct IP addresses, networks, cities, and user agents within a 30-minute window, excluding console login sessions and known automation frameworks like Terraform or Ansible. Such a high-fidelity pattern strongly suggests credential compromise and subsequent unauthorized access within an AWS environment, necessitating immediate investigation to prevent further malicious activity such as data exfiltration or resource manipulation.

## Attack Chain

1. **Initial Access / Credential Compromise**: An attacker gains initial access to an AWS user's workstation or environment, possibly through phishing, malware, or exploiting a vulnerable application.
2. **Credential Theft**: The attacker identifies and steals temporary AWS IAM session tokens, which could be active session cookies, environment variables, or other stored credentials.
3. **Deployment from Attack Infrastructure**: The attacker initiates activities in the target AWS environment using the stolen temporary session token from their command and control (C2) infrastructure, which uses a distinct IP address, network, and user agent different from the legitimate user's.
4. **Geographic Evasion**: To further obscure their activity, the attacker might quickly switch to another C2 node located in a different city or region, leveraging the same stolen session token.
5. **Multi-Platform Access**: The attacker might switch user agents or client applications to interact with AWS APIs, mimicking different types of clients (e.g., CLI, custom script).
6. **Reconnaissance and Enumeration**: Using the compromised token, the attacker performs reconnaissance activities, such as `s3:ListBuckets`, `iam:ListUsers`, or `sts:GetCallerIdentity` to understand the environment and identify targets.
7. **Resource Manipulation / Data Exfiltration**: Based on the gathered intelligence and permissions of the compromised token, the attacker performs unauthorized actions, such as modifying resources, escalating privileges, or exfiltrating sensitive data from S3 buckets.
8. **Persistence (Optional)**: If the token allows, the attacker might attempt to establish more persistent access mechanisms before the temporary token expires or is revoked.

## Impact

The successful exploitation of compromised AWS IAM session tokens can lead to severe consequences, including unauthorized access to cloud resources, exposure or exfiltration of sensitive data, modification or deletion of critical infrastructure, and potentially the deployment of ransomware or cryptominers within the victim's AWS environment. Such incidents can result in significant financial losses, operational disruption, reputational damage, and non-compliance penalties. While specific victim numbers are not provided, organizations heavily reliant on AWS for their operations and data storage are the primary targets, and any AWS user with temporary session tokens is vulnerable if their credentials are compromised.

## Recommendation

* Deploy the correlation logic described in this brief within your SIEM using `aws.cloudtrail` logs to detect IAM session token usage from multiple distinct IPs, networks, cities, and user agents.
* Ensure comprehensive `aws.cloudtrail` logging is enabled across all AWS accounts and regions, forwarding logs to your SIEM for analysis.
* Regularly review and revoke any IAM credentials that are suspected of being compromised, including temporary session tokens.
* Implement strong multi-factor authentication (MFA) requirements for all IAM users, especially for those with elevated privileges, and enforce MFA for actions requiring temporary credentials where possible.
* Audit the environment for signs of lateral movement or data access subsequent to any alert indicating a compromised token.
* Restrict access to AWS resources via policy conditions, such as specifying allowed IP ranges or device types, to limit the blast radius of compromised credentials.
