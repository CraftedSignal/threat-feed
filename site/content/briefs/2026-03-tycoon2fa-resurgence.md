---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-03-tycoon2fa-resurgence
description: The Tycoon2FA PhaaS platform, used for MFA bypass and email compromise, has demonstrated a resurgence in activity following a law enforcement takedown, indicating continued threat actor activity.
date: "2026-03-31T12:00:00Z"
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
  - tycoon2fa
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
  - title: Detect Tycoon2FA CAPTCHA Page Redirection
    description: Detects potential phishing attempts where users are redirected to a Tycoon2FA CAPTCHA page, indicating a possible credential harvesting attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Session Cookie Theft via JavaScript
    description: Detects potential session cookie theft attempts by identifying suspicious JavaScript execution that attempts to access or transmit cookie data.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Tycoon2FA platform is a subscription-based Phishing-as-a-Service (PhaaS) that enables cybercriminals to bypass multi-factor authentication (MFA) and compromise email accounts. First observed in 2023, the platform gained notoriety and in mid-2025 was reportedly responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. On March 4, 2026, Europol announced a technical disruption, seizing 330 domains associated with the platform. Despite this takedown, CrowdStrike Falcon Complete observed a short-term decrease in campaign activity, followed by a return to pre-disruption levels. This indicates the actors behind Tycoon2FA are likely to remain active and adapt their TTPs to maintain pressure on defenders. The platform's continued operation underscores the resilience of PhaaS models and the need for persistent monitoring and defense.

## Attack Chain

1.  **Initial Phishing Email:** Victims receive a phishing email designed to lure them to a malicious website.
2.  **Tycoon2FA CAPTCHA Page:** Victims are directed to a Tycoon2FA-controlled CAPTCHA page.
3.  **Session Cookie Theft:** Upon CAPTCHA validation, the victim's session cookies are stolen using JavaScript.
4.  **Email Address Extraction:** A JavaScript file extracts the victim’s email address.
5.  **Fake Login Page:** The victim is presented with a fake Microsoft 365 or Google login page hosted on a Tycoon2FA domain.
6.  **Credential Proxying:** The victim's credentials are proxied to a legitimate Microsoft 365 cloud account via an obfuscated JavaScript file.
7.  **Cloud Environment Access:** The attacker authenticates to the victim’s cloud environment using the stolen cookies and credentials.
8.  **Account Compromise:** With access to the account, the attacker can perform malicious activities, such as sending further phishing emails or exfiltrating data.

## Impact

Tycoon2FA has been a significant contributor to phishing campaigns since 2023. In mid-2025, the platform was responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. Successful attacks lead to compromised email accounts, potential data exfiltration, and further propagation of phishing campaigns. The resurgence of Tycoon2FA following the takedown suggests a persistent threat, requiring ongoing vigilance and defensive measures.

## Recommendation

*   Deploy the "Detect Tycoon2FA CAPTCHA Page Redirection" Sigma rule to identify potential phishing attempts leading to the malicious CAPTCHA pages (rules).
*   Monitor network traffic for connections to domains associated with Tycoon2FA to identify compromised systems (IOCs).
*   Deploy the "Detect Session Cookie Theft via JavaScript" Sigma rule to identify attempts to steal session cookies (rules).
*   Enhance user awareness training to educate users about the tactics used by Tycoon2FA, including CAPTCHA-based phishing and fake login pages.
*   Implement MFA and monitor for bypass attempts, as Tycoon2FA specializes in circumventing these controls.
