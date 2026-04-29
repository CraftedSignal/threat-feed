---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, used to bypass MFA and compromise email accounts, has rebounded after a law enforcement takedown, with campaign activity and tactics returning to pre-disruption levels.
date: "2026-03-31T01:45:17Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - credential-theft
  - mfa-bypass
  - phaas
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
rules:
  - title: Detect Tycoon2FA Phishing Redirection
    description: Detects process creation events indicative of a user being redirected to a Tycoon2FA phishing page after clicking a link in a phishing email.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Tycoon2FA Cookie Theft via JavaScript
    description: Detects JavaScript files attempting to steal cookies, a technique used by Tycoon2FA to bypass MFA.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Tycoon2FA is a subscription-based Phishing-as-a-Service (PhaaS) platform that enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. On March 4, 2026, Europol announced a technical disruption of Tycoon2FA, seizing 330 domains that formed the platform's core infrastructure. Despite this takedown, CrowdStrike observed only a short-term decrease in Tycoon2FA campaign activity. The volume of cloud compromises has since increased to levels previously observed. The continued use of previously observed Tycoon2FA tactics, techniques, and procedures (TTPs) suggests that the actors responsible for the PhaaS are likely to remain active in the threat landscape, requiring continued vigilance. Tycoon2FA began operations in 2023 and was responsible for a large percentage of phishing attempts blocked by Microsoft in 2025.

## Attack Chain

1.  Victims receive phishing emails designed to entice them to click malicious links.
2.  The links redirect victims to Tycoon2FA CAPTCHA pages.
3.  Upon CAPTCHA validation, victims' session cookies are stolen.
4.  A JavaScript (JS) file extracts victims' email addresses.
5.  Victims are presented with fake Microsoft 365 or Google login pages hosted on a Tycoon2FA domain.
6.  Victims enter their credentials, which are then proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
7.  Attackers authenticate to the victim's cloud environment using the stolen cookies and credentials.
8.  Attackers gain access to the victim's email and other cloud resources, enabling data theft, business email compromise, or further malicious activities.

## Impact

Tycoon2FA was responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025 and purportedly generated over 30 million malicious emails in a single month. Successful attacks lead to account compromise, data theft, and potential business email compromise, resulting in financial loss and reputational damage. Despite the takedown of 330 domains, the platform's resurgence demonstrates the resilience of PhaaS operations.

## Recommendation

*   Monitor network traffic for connections to newly registered domains, as threat actors may use new infrastructure to host Tycoon2FA phishing pages (network_connection).
*   Implement and tune the "Detect Tycoon2FA Phishing Redirection" Sigma rule to identify potential phishing attempts (process_creation, network_connection).
*   Implement and tune the "Detect Tycoon2FA Cookie Theft via JavaScript" Sigma rule to detect cookie theft attempts (file_event, process_creation).
*   Educate users to identify and avoid phishing emails, especially those requesting CAPTCHA validation or redirecting to unfamiliar login pages (T1566).
