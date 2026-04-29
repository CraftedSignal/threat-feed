---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence
slug: 2026-03-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, which enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts, has shown resilience following a takedown attempt by Europol on March 4, 2026, with campaign activity returning to pre-disruption levels and consistent TTPs.
date: "2026-03-30T06:40:37Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - MFA-bypass
  - cloud-compromise
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
  - title: Detect JavaScript Email Address Extraction
    description: Detects JavaScript files used to extract email addresses, a technique used by Tycoon2FA.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - file_event
      - windows
  - title: Detect Fake Microsoft 365 Login Page Access
    description: Detects access to domains known to host fake Microsoft 365 login pages, a common tactic used in phishing campaigns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect suspicious process creating network connections
    description: Detects processes making network connections that are not usually associated with network activity
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The Tycoon2FA phishing-as-a-service (PhaaS) platform, disrupted by Europol on March 4, 2026, has demonstrated a resurgence in activity, indicating the platform's operators remain active and adaptable. Tycoon2FA, active since 2023, enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts through adversary-in-the-middle (AITM) techniques. Before the takedown, in mid-2025, it was responsible for 62% of all phishing attempts blocked by Microsoft and purportedly generated over 30 million malicious emails in a single month. While a short-term decrease in campaign activity was observed immediately following the takedown of 330 domains comprising its core infrastructure, the volume of cloud compromises has since returned to pre-disruption levels, and the platform's TTPs have remained consistent, emphasizing the need for continued vigilance by defenders.

## Attack Chain

1. Victims receive phishing emails directing them to Tycoon2FA CAPTCHA pages.
2. Upon CAPTCHA validation, the platform steals the victim's session cookies.
3. A JavaScript (JS) file is used to extract the victim's email address.
4. The victim is presented with a fake Microsoft 365 or Google login page hosted on a Tycoon2FA domain.
5. Victim credentials are proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
6. Stolen cookies and credentials are used to authenticate to the victim's cloud environment.
7. Attackers gain access to the victim's email and other cloud-based resources.
8. The compromised accounts are used for further malicious activities, such as data theft, business email compromise (BEC), or lateral movement.

## Impact

The Tycoon2FA platform facilitates the compromise of email accounts and cloud environments, enabling attackers to bypass MFA. Before the takedown, the platform was responsible for a significant portion of phishing attempts, blocking 62% of attempts blocked by Microsoft in mid-2025. A single month saw 30 million malicious emails being attributed to this platform. Successful attacks can lead to data breaches, financial losses through BEC, and further propagation of attacks. The resurgence of Tycoon2FA following the takedown suggests that defenders must remain vigilant and adapt their detection and response strategies.

## Recommendation

*   Monitor network traffic for connections to newly registered domains, especially those mimicking legitimate Microsoft or Google login pages, using a network_connection rule.
*   Deploy the Sigma rule detecting the execution of JavaScript files that extract email addresses to identify potential cookie-stealing attempts from Tycoon2FA.
*   Investigate any authentication events to Microsoft 365 or Google Cloud Platform originating from unusual locations or devices, correlating with possible session cookie theft.
*   Monitor process creation events for unusual JavaScript execution within the context of browser processes, indicative of credential harvesting attempts, and tune the provided process_creation Sigma rule for your environment.
