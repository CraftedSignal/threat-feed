---
title: Okta FastPass Phishing Attempt Detection
slug: 2024-01-okta-fastpass-phishing
description: Okta FastPass detected and prevented a phishing attempt, indicating a user was likely targeted with a credential harvesting attack.
date: "2024-01-03T12:00:00Z"
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

This alert identifies instances where Okta FastPass successfully blocked a user authentication attempt due to a detected phishing attack. This is based on Okta system logs that record when FastPass declines an authentication because the user was attempting to log in to a known phishing site. The event indicates that a user was likely targeted via phishing, potentially through email or other means, and entered their Okta credentials into a fraudulent site. While the authentication was blocked…
