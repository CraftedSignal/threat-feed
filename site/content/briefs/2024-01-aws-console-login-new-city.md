---
title: AWS Console Login from New City
slug: 2024-01-aws-console-login-new-city
description: A user logging into the AWS console from a previously unseen city could indicate compromised credentials or an insider threat.
date: "2024-01-03T12:00:00Z"
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
  - Amazon
products:
  - AWS Management Console
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/detect_aws_console_login_by_user_from_new_city.yml
rules:
  - title: AWS Console Login from New City
    description: Detects AWS console logins from a city not previously seen for a given user.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloud
      - aws
  - title: AWS Console Login - Unexpected City (Baseline Deviation)
    description: This rule detects when a user logs into the AWS console from a city that deviates from their established baseline.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloud
      - aws
rules_count: 2
---

This alert detects when a user logs into the AWS console from a city that they have never logged in from before. This behavior is anomalous and could indicate that the user's credentials have been compromised and are being used by an attacker in a different location. It could also be a sign of an insider threat, where a legitimate user is accessing resources from an unexpected location for malicious purposes. Defenders should investigate any such alerts to determine the cause of the anomalous login and take appropriate action. This detection focuses on identifying deviations from established user behavior patterns.

## Attack Chain

1. Initial Access: An attacker obtains valid AWS credentials through phishing, credential stuffing, or other means.
2. Console Login: The attacker uses the stolen credentials to log into the AWS Management Console.
3. Geolocation Check: The AWS login event includes the user's IP address, which is then geolocated to a city.
4. Anomaly Detection: The city is compared to a historical list of cities from which the user has previously logged in.
5. Alert Trigger: If the city is new for that user, an alert is triggered.
6. Potential Lateral Movement: The attacker leverages the console access to explore the AWS environment.
7. Resource Access: The attacker may access sensitive data, modify configurations, or launch new resources.
8. Impact: Data exfiltration, service disruption, or unauthorized resource consumption.

## Impact

A successful attack could lead to unauthorized access to sensitive data, modification of critical configurations, or the deployment of malicious resources within the AWS environment. This could result in data breaches, service disruptions, or financial losses. The impact is highly dependent on the permissions associated with the compromised user account and the attacker's objectives. A single compromised account can affect multiple services and resources within the AWS infrastructure.
