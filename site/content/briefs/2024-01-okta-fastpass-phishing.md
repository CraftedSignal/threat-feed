---
title: Okta FastPass Phishing Attempt Detection
slug: 2024-01-okta-fastpass-phishing
description: Okta FastPass detected and prevented a phishing attempt, indicating a user was likely targeted with a credential harvesting attack.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - okta
  - fastpass
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://sec.okta.com/fastpassphishingdetection
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta FastPass Phishing Detection
    description: Detects when Okta FastPass prevents a known phishing site.
    platform: sigma
    severity: high
    tactics:
      - initial-access
    techniques:
      - T1566
    data_sources:
      - okta
      - okta
  - title: Okta MFA Authentication Failures from New Geolocation
    description: Detects Okta MFA authentication failures originating from previously unseen geographical locations, potentially indicating account compromise.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1566
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert identifies instances where Okta FastPass successfully blocked a user authentication attempt due to a detected phishing attack. This is based on Okta system logs that record when FastPass declines an authentication because the user was attempting to log in to a known phishing site. The event indicates that a user was likely targeted via phishing, potentially through email or other means, and entered their Okta credentials into a fraudulent site. While the authentication was blocked, the event warrants investigation to determine the scope of the phishing campaign and whether the user may have entered credentials elsewhere.

## Attack Chain

1. An attacker crafts a phishing email or message mimicking a legitimate Okta login page.
2. The user receives the phishing message and clicks the embedded link.
3. The user is directed to a fake Okta login page that is designed to steal credentials.
4. The user enters their Okta username and password on the phishing site.
5. The phishing site attempts to authenticate the user to Okta using the stolen credentials.
6. Okta FastPass detects that the authentication attempt is originating from a known phishing site.
7. Okta FastPass declines the authentication request, preventing access.
8. The Okta system logs record the event "user.authentication.auth_via_mfa" with outcome "FAILURE" and reason "FastPass declined phishing attempt".

## Impact

While Okta FastPass successfully prevented the immediate breach, the incident confirms that a user was targeted by a phishing campaign. This could lead to the compromise of other accounts if the user reuses the same password. Furthermore, successful phishing attacks can lead to data breaches, financial loss, and reputational damage. The number of affected users depends on the scale of the phishing campaign.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect Okta FastPass phishing prevention events.
*   Investigate users who triggered the detection to identify the phishing campaign and assess potential credential compromise.
*   Review Okta system logs for other suspicious activity associated with the targeted user accounts.
*   Educate users about phishing tactics and how to identify malicious websites to reduce susceptibility to future attacks.
