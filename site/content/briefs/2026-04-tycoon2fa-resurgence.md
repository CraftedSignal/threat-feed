---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, which bypasses multifactor authentication (MFA) to compromise email accounts, experienced a temporary disruption following a law enforcement takedown, but campaign volumes and tactics have returned to pre-disruption levels, indicating the actors are likely to remain active.
date: "2026-03-28T14:49:20Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - mfa bypass
  - credential theft
  - cloud
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
  - title: Detect Suspicious Javascript Cookie Theft
    description: Detects Javascript attempting to access or modify document.cookie which could indicate cookie theft.
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
    description: Detects access to fake Microsoft 365 or Google login pages.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect CAPTCHA Page Access Prior to Login Attempt
    description: Detects access to a CAPTCHA page followed by a login attempt within a short timeframe, which is indicative of Tycoon2FA's technique.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
rules_count: 3
---

On March 4, 2026, Europol announced the takedown of Tycoon2FA, a subscription-based phishing-as-a-service (PhaaS) platform used by cybercriminals to bypass multi-factor authentication (MFA) and compromise email accounts. The coordinated effort involved law enforcement agencies from six countries and resulted in the seizure of 330 domains that constituted the platform's core infrastructure. Despite this disruption, CrowdStrike Falcon Complete observed a short-term decrease in Tycoon2FA campaign activity, followed by a return to pre-disruption levels, with no change in TTPs. This suggests the actors behind the PhaaS are likely to remain active in the short to medium term, targeting cloud environments. In mid-2025, the platform was responsible for 62% of all phishing attempts blocked by Microsoft, purportedly generating over 30 million malicious emails in a single month.

## Attack Chain

1.  Victims receive phishing emails directing them to Tycoon2FA CAPTCHA pages.
2.  Upon CAPTCHA validation, victims' session cookies are stolen.
3.  A JavaScript (JS) file extracts victims' email addresses.
4.  Fake Microsoft 365 or Google login pages, hosted on a Tycoon2FA domain, are displayed to the victim.
5.  Victims' credentials are proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
6.  The attacker authenticates to the victim's cloud environment using the stolen cookies and credentials.
7.  Attackers gain access to the victim's email, calendar, and other cloud-based resources.
8.  Attackers may then use the compromised account to send further phishing emails, steal sensitive data, or perform other malicious activities.

## Impact

The Tycoon2FA platform, active since 2023, was responsible for a significant portion of phishing attempts, with 62% of those blocked by Microsoft in mid-2025 attributed to the platform, totaling over 30 million emails in a single month. A successful attack can lead to unauthorized access to sensitive data, business email compromise, and further propagation of phishing campaigns. Victims whose accounts are compromised face data theft, financial loss, and reputational damage. The persistence of Tycoon2FA, even after a takedown, demonstrates the resilience of PhaaS platforms and the ongoing need for robust security measures.

## Recommendation

*   Monitor network traffic for connections to newly registered domains similar to those previously associated with Tycoon2FA (IOC table) using network_connection logs.
*   Implement and tune the provided Sigma rules to detect suspicious JavaScript execution patterns indicative of Tycoon2FA's credential harvesting techniques (Sigma rule).
*   Educate users on identifying and avoiding phishing emails that lead to fake login pages (attack chain, step 1).
*   Deploy detection rules that alert on session cookie theft and unauthorized cloud account access using stolen credentials (attack chain, steps 2 and 6).
*   Continuously monitor cloud environments for unusual login activity, especially from unfamiliar locations or devices (attack chain, step 6).
