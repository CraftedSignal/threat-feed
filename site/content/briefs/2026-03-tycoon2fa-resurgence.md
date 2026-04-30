---
title: Tycoon2FA PhaaS Platform Resurgence After Takedown
slug: 2026-03-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, disrupted in March 2026, has resurged with consistent tactics, employing adversary-in-the-middle (AITM) techniques to bypass MFA and compromise email accounts through phishing campaigns, credential theft, and session cookie hijacking.
date: "2026-03-28T08:28:28Z"
type: advisory
types:
  - advisory
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
    technique_id: T1539
    technique_name: Steal Web Session Cookie
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
iocs:
  - type: email
    value: phishing emails
ioc_counts:
  email: 1
rules:
  - title: Detect Email Address Extraction via JavaScript
    description: Detects JavaScript code attempting to extract email addresses from web pages, a technique used by Tycoon2FA.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Fake Microsoft 365 Login Page
    description: Detects access to fake Microsoft 365 login pages hosted on suspicious domains.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tycoon2FA is a subscription-based PhaaS platform that enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts using adversary-in-the-middle (AITM) techniques. The platform gained prominence in 2025, reportedly generating over 30 million malicious emails in a single month and accounting for 62% of all phishing attempts blocked by Microsoft at one point. On March 4, 2026, Europol announced a technical disruption of Tycoon2FA, seizing 330 domains forming the platform’s core infrastructure. Despite this takedown, CrowdStrike Falcon Complete observed a short-term decrease in Tycoon2FA activity followed by a return to pre-disruption levels. The persistence of the platform's original tactics, techniques, and procedures (TTPs) suggests that the actors behind Tycoon2FA remain active and pose a continued threat. Defenders should maintain vigilance.

## Attack Chain

1.  Victims receive phishing emails designed to appear legitimate.
2.  These emails direct victims to Tycoon2FA CAPTCHA pages hosted on attacker-controlled domains.
3.  Upon CAPTCHA validation, a JavaScript (JS) file extracts the victim's email address.
4.  The victim is then redirected to a fake Microsoft 365 or Google login page hosted on a Tycoon2FA domain.
5.  Victims enter their credentials, which are proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
6.  The attacker steals the victim's session cookies and credentials.
7.  The attacker authenticates to the victim's cloud environment using the stolen cookies and credentials.
8.  The attacker gains access to the victim's email and other cloud-based resources, potentially leading to data exfiltration or further malicious activity.

## Impact

Tycoon2FA's operations began in 2023, and by mid-2025, it was responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. A successful attack can lead to unauthorized access to sensitive data, business email compromise, financial loss, and reputational damage. The resurgence of Tycoon2FA following the takedown indicates the platform remains a significant threat, highlighting the need for robust defenses against phishing and credential theft.

## Recommendation

*   Monitor email traffic for unusual patterns and sender addresses to detect phishing attempts associated with Tycoon2FA (IOC: phishing emails).
*   Implement and tune web filtering rules to block access to known Tycoon2FA domains and newly registered domains that may be used for phishing campaigns (IOC: Tycoon2FA domain).
*   Deploy the Sigma rule to detect JavaScript files that attempt to extract email addresses from web pages, a technique used by Tycoon2FA to target victims.
*   Review and reinforce MFA policies and educate users about the risks of phishing and credential theft.
