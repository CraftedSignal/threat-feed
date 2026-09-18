---
title: Detection of Adversary-in-the-Middle Session Theft via Geographic Implausibility
slug: 2026-09-aws-console-geo-anomaly
description: This brief describes a method for detecting Adversary-in-the-Middle (AiTM) phishing and session theft in AWS environments by identifying IAM user console logins originating from geographically distinct locations within a short timeframe.
date: "2026-09-18T19:35:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - aws
  - session-theft
  - identity
vendors:
  - Amazon
products:
  - AWS Management Console
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The detection rule identifies an IAM user that successfully signs in to the AWS Management Console from two or more distinct countries within a short window.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: Concurrent sign-ins from different geographies indicate the credentials or console session are in use from more than one location, a strong signal of adversary-in-the-middle (AiTM) phishing or session theft.
    confidence_band: high
references:
  - https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-kit-and-beyond/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/initial_access_console_login_iam_user_multiple_geolocations.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy geographical anomaly detection for AWS console logins.
      owner: Detection Engineering
      due: 72h
      evidence: Source documentation for AWS IAM user session theft detection.
  mitigation_plan:
    - priority: immediate
      action: Migrate console access to IAM Identity Center using FIDO2 phishing-resistant MFA.
      owner: IT Operations
      addresses: Adversary-in-the-middle session relay
      evidence: Source response and remediation documentation.
---

Adversary-in-the-middle (AiTM) phishing kits represent a significant threat to cloud authentication by capturing both credentials and multi-factor authentication (MFA) tokens in real-time. When an attacker utilizes these stolen session cookies to access the AWS Management Console, they operate from their own infrastructure, which is often geographically divergent from the legitimate user's location. This activity results in physically implausible login patterns where the same IAM user account authenticates from two or more distinct countries within a very brief window. 

Defenders can identify this activity by monitoring AWS CloudTrail 'ConsoleLogin' events for successful authentications that occur in rapid succession from different geographic regions. This detection logic serves as a cloud-native equivalent to identity-provider impossible-travel alerts, providing high-fidelity signal for account compromise even when MFA challenges appear successfully satisfied, as the AiTM kit relays these challenges to the victim during the initial phishing interaction.

## Impact

Successful exploitation of this technique allows unauthorized actors to bypass MFA-protected login flows, gaining persistent or transient access to AWS management interfaces. If undetected, this can lead to privilege escalation, data exfiltration, and unauthorized changes to IAM policies or access keys. Impacted organizations face potential exposure of critical cloud resources and sensitive data.

## Recommendation

Prioritize the implementation of geographic-based anomaly detection for AWS console logins to identify session theft. 

- Deploy detection logic to aggregate 'ConsoleLogin' events by IAM user identity and flag instances where the user successfully authenticates from multiple distinct countries within a 65-minute window.
- Review all flagged events by inspecting the 'source_geo_country_iso_code' and 'source_ip' values in CloudTrail to confirm if the activity aligns with expected user behavior or known VPN/proxy egress points.
- Evaluate the use of IAM Identity Center with phishing-resistant MFA, specifically FIDO2/passkey hardware tokens, which natively defeat AiTM relay attacks.
- Conduct an immediate response review for any account triggering this alert, including resetting passwords, revoking active console sessions, and rotating access keys.
