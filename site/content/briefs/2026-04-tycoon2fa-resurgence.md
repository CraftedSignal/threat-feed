---
title: Tycoon2FA PhaaS Platform Resurgence Following Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, disrupted by law enforcement on March 4, 2026, has shown a resurgence in activity, enabling cybercriminals to bypass MFA and compromise email accounts using adversary-in-the-middle (AITM) techniques.
date: "2026-03-30T06:31:25Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - mfa-bypass
  - aitm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1005
    technique_name: Data from Local System
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Redirection to Fake CAPTCHA Pages
    description: Detects redirection to potentially malicious CAPTCHA pages, which may indicate a phishing attack using Tycoon2FA.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious JavaScript for Email Extraction
    description: Detects JavaScript files being served that are used for extracting email addresses, a common technique in Tycoon2FA attacks.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, which was subject to a coordinated takedown by Europol and law enforcement agencies on March 4, 2026, has demonstrated a resurgence in malicious activity. Tycoon2FA, operating since 2023, provides a subscription-based service enabling cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts through adversary-in-the-middle (AITM) techniques. The takedown resulted in the seizure of 330 domains associated with the platform. Despite this disruption, CrowdStrike Falcon Complete observed a return to pre-disruption campaign volumes shortly after the takedown, with no significant changes in the platform's tactics, techniques, and procedures (TTPs). This suggests the actors behind Tycoon2FA are resilient and continue to pose a threat. In mid-2025, the platform was responsible for 62% of all phishing attempts blocked by Microsoft and purportedly generated more than 30 million malicious emails in a single month.

## Attack Chain

1.  **Initial Phishing Email:** The attack begins with a phishing email sent to the victim, designed to appear legitimate and trustworthy.
2.  **Redirection to Tycoon2FA CAPTCHA Page:** Victims who click the link in the email are redirected to a Tycoon2FA-controlled CAPTCHA page.
3.  **CAPTCHA Validation and Session Cookie Theft:** Upon successful CAPTCHA validation, the victim's session cookies are stolen by the Tycoon2FA platform.
4.  **Email Address Extraction:** The platform extracts the victim's email address using a JavaScript (JS) file.
5.  **Fake Login Page Population:** The stolen email address is used to populate a fake Microsoft 365 or Google login page hosted on a Tycoon2FA domain.
6.  **Credential Proxying:** When the victim enters their credentials, they are proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
7.  **Authentication via Stolen Credentials:** The attacker authenticates to the victim's cloud environment using the stolen cookies and credentials.
8.  **Account Compromise:** With successful authentication, the attacker gains access to the victim's email account and other cloud resources, enabling data theft, further phishing attacks, or other malicious activities.

## Impact

Tycoon2FA has been responsible for a significant portion of phishing attacks, with 62% of phishing attempts blocked by Microsoft in mid-2025 attributed to the platform. It has been used to generate more than 30 million malicious emails in a single month. The platform's resurgence after the takedown indicates that organizations remain vulnerable to MFA bypass and email account compromise, potentially leading to data breaches, financial losses, and reputational damage. A successful attack can give threat actors access to sensitive data and allow them to launch further attacks within the compromised organization.

## Recommendation

*   Monitor network traffic for connections to known Tycoon2FA infrastructure, even if previous IOCs are no longer active.
*   Deploy the Sigma rule targeting redirection to fake CAPTCHA pages to detect initial access attempts.
*   Review and enhance MFA policies to mitigate AITM attacks, as Tycoon2FA is designed to bypass standard MFA implementations.
*   Implement the Sigma rule that detects suspicious JavaScript files used for email address extraction, to identify potential data harvesting activity.
*   Educate users to identify and avoid phishing attempts, emphasizing the importance of verifying URL legitimacy before entering credentials.
