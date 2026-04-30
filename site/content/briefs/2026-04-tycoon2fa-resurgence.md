---
title: Tycoon2FA Phishing-as-a-Service Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service platform, used to bypass multifactor authentication (MFA), has resurged to pre-takedown levels of activity following a disruption effort in March 2026, maintaining its original tactics, techniques, and procedures (TTPs) for credential harvesting and cloud compromise.
date: "2026-03-28T08:20:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - credential-theft
  - MFA-bypass
  - phishing-as-a-service
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
iocs:
  - type: email
    value: phishing emails
ioc_counts:
  email: 1
rules:
  - title: Tycoon2FA Phishing Redirection
    description: Detects potential phishing attempts redirecting to Tycoon2FA infrastructure by identifying suspicious redirects to known CAPTCHA pages or fake login pages.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Tycoon2FA Cookie Theft via JavaScript
    description: Detects potential cookie theft attempts via malicious JavaScript files associated with Tycoon2FA campaigns.
    platform: sigma
    severity: medium
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

On March 4, 2026, Europol announced a technical disruption of the Tycoon2FA Phishing-as-a-Service (PhaaS) platform, which enabled cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. The takedown involved seizing 330 domains that formed the platform’s core infrastructure. However, following the takedown, CrowdStrike observed only a short-term decrease in Tycoon2FA campaign activity. The volume of cloud compromises has since returned to pre-disruption levels, and the platform continues to employ previously observed TTPs. Tycoon2FA, active since 2023, was responsible for a significant portion of phishing attempts, purportedly generating over 30 million malicious emails in a single month in mid-2025. The platform primarily targets Microsoft 365 and Google accounts using adversary-in-the-middle (AITM) techniques.

## Attack Chain

1.  Victims receive phishing emails directing them to Tycoon2FA CAPTCHA pages.
2.  Upon CAPTCHA validation, victims' session cookies are stolen.
3.  A JavaScript (JS) file is used to extract victims’ email addresses.
4.  Victims are redirected to fake Microsoft 365 or Google login pages hosted on a Tycoon2FA domain.
5.  Victims enter their credentials into the fake login pages, which are then proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
6.  The threat actor authenticates to the victim’s cloud environment using the stolen cookies and credentials.
7.  Once authenticated, the attacker gains access to the victim's email and other cloud resources.
8.  The attacker can then perform actions such as data exfiltration, sending phishing emails to other targets, or further compromising the organization's environment.

## Impact

The resurgence of Tycoon2FA demonstrates the resilience of PhaaS platforms and their operators. The platform was responsible for a large percentage of phishing attacks in 2025, including 62% of all phishing attempts blocked by Microsoft in mid-2025, and generating over 30 million malicious emails in a single month. Successful attacks can lead to unauthorized access to sensitive data, financial losses, and reputational damage. The observed return to pre-disruption activity levels indicates a sustained threat to organizations relying on MFA for account security.

## Recommendation

*   Deploy the "Tycoon2FA Phishing Redirection" Sigma rule to detect potential phishing attempts redirecting to Tycoon2FA infrastructure.
*   Monitor email traffic for patterns indicative of phishing campaigns, focusing on emails directing users to external login pages, as described in the Attack Chain.
*   Implement strict session management policies and regularly review user authentication logs for suspicious activity following successful authentication as described in the attack chain, step 7.
*   Block known Tycoon2FA domains at the DNS resolver, as referenced in the IOC section.
*   Educate users about the tactics used by Tycoon2FA, specifically the use of CAPTCHA pages to steal session cookies, as described in the Attack Chain, step 2.
