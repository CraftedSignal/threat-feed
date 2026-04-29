---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service platform, which bypasses MFA, has resurged to pre-takedown activity levels, indicating continued risk despite law enforcement disruption efforts.
date: "2026-03-31T08:36:16Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - credential-theft
  - MFA-bypass
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Redirection to Tycoon2FA CAPTCHA Pages
    description: Detects potential phishing attempts redirecting users to Tycoon2FA CAPTCHA pages
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect JavaScript Email Address Extraction
    description: Detects suspicious JavaScript files attempting to extract email addresses
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Tycoon2FA is a subscription-based phishing-as-a-service (PhaaS) platform that allows cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. The platform began operations in 2023 and by mid-2025 was responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. On March 4, 2026, Europol disrupted the platform by seizing 330 domains. Despite this takedown, CrowdStrike Falcon Complete observed a short-term decrease in activity followed by a return to pre-disruption levels. This indicates the actors behind Tycoon2FA remain active and adaptable, requiring continued vigilance from defenders. The platform's persistence underscores the challenge of disrupting PhaaS operations and the need for robust detection and response capabilities.

## Attack Chain

1.  Victims receive phishing emails directing them to Tycoon2FA CAPTCHA pages.
2.  Upon CAPTCHA validation, victims' session cookies are stolen.
3.  Victims are redirected to fake Microsoft 365 or Google login pages hosted on a Tycoon2FA domain.
4.  A JavaScript (JS) file extracts the victim's email address.
5.  The victim's credentials are proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
6.  The attacker authenticates to the victim's cloud environment using the stolen cookies and credentials.
7.  Once authenticated, the attacker can access sensitive data, send phishing emails to other targets, or perform other malicious activities.

## Impact

The Tycoon2FA platform has enabled widespread email account compromise, with 62% of all phishing attempts blocked by Microsoft in mid-2025 attributed to the platform, resulting in over 30 million malicious emails in a single month. Successful attacks lead to unauthorized access to sensitive information, potential business email compromise (BEC), and further propagation of phishing campaigns. The resurgence of Tycoon2FA after the takedown highlights the persistent threat to organizations relying on MFA and cloud-based services.

## Recommendation

*   Monitor email traffic for redirects to unusual CAPTCHA pages, and deploy the Sigma rule `Detect Redirection to Tycoon2FA CAPTCHA Pages` to detect this behavior.
*   Implement detections for session cookie theft attempts and monitor for suspicious logins from unusual locations, leveraging the IOCs identified.
*   Monitor network traffic for connections to known Tycoon2FA domains.
*   Educate users to recognize and report phishing emails, especially those requesting CAPTCHA validation.
*   Enrich existing detections by looking for the TTPs described in the attack chain.
