---
title: AWS Console Login by User from New Country
slug: 2024-01-aws-console-login-new-country
description: This detection identifies AWS console logins by a user originating from a country not previously associated with that user, potentially indicating account compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloud
  - identity
  - account-compromise
vendors:
  - AWS
products:
  - AWS Management Console
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/detect_aws_console_login_by_user_from_new_country.yml
rules:
  - title: AWS Console Login From New Country
    description: Detects AWS console logins from a country not previously seen for a user.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Console Login without MFA
    description: Detects AWS Console logins that did not use MFA.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies instances of AWS console logins where a user authenticates from a country that is not within their historical login locations. The goal is to detect potential account compromise scenarios where an attacker gains access to a legitimate user's AWS credentials and logs in from a geographically anomalous location. While not all such logins are malicious, they warrant investigation to confirm the user's activity and ensure no unauthorized access is occurring. This rule leverages the AWS CloudTrail logs to monitor console login events and compare the source country with a baseline of previously observed countries for each user.

## Attack Chain

1.  Attacker gains access to AWS credentials through phishing, credential stuffing, or malware.
2.  Attacker uses the stolen credentials to attempt to log in to the AWS Management Console.
3.  The login attempt generates a CloudTrail event.
4.  The CloudTrail event records the source IP address of the login attempt.
5.  Geolocation services determine the country of origin for the source IP address.
6.  The detected country is compared against a historical baseline of countries associated with the user.
7.  If the country is new for the user, an alert is triggered.

## Impact

Successful exploitation can lead to unauthorized access to sensitive AWS resources. This may result in data breaches, service disruption, or financial loss. The impact depends on the permissions associated with the compromised user account. Early detection of anomalous login activity can prevent significant damage by allowing security teams to quickly investigate and remediate the incident, such as disabling the compromised account or enforcing multi-factor authentication.
