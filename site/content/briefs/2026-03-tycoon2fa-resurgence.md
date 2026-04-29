---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-03-tycoon2fa-resurgence
description: The Tycoon2FA PhaaS platform, used to bypass MFA and compromise email accounts, has demonstrated resilience following a takedown attempt, with cloud compromise activity returning to pre-disruption levels and actors maintaining previously observed tactics.
date: "2026-03-28T09:27:11Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - credential-theft
  - mfa-bypass
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
  - title: Detect Tycoon2FA PhaaS Redirection
    description: Detects potential phishing attempts redirecting to Tycoon2FA infrastructure by identifying redirects to suspicious domains mimicking legitimate login pages.
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
  - title: Detect Tycoon2FA PhaaS Cookie Theft
    description: Detects potential cookie theft attempts by identifying network connections originating from uncommon processes accessing common credential URLs, indicative of session hijacking.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 4, 2026, Europol announced the technical disruption of Tycoon2FA, a subscription-based phishing-as-a-service (PhaaS) platform used by cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. The takedown involved seizing 330 domains that formed the platform's core infrastructure. Despite this disruption, CrowdStrike Falcon Complete Next-Gen MDR team observed a short-term decrease followed by a return to pre-disruption levels of cloud compromises. The actors responsible for Tycoon2FA continue to use previously observed tactics, techniques, and procedures (TTPs), indicating that the platform is likely to remain active in the threat landscape and requires continued vigilance from defenders. Tycoon2FA began its operations in 2023 and was responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025, generating over 30 million malicious emails in a single month.

## Attack Chain

1.  The attack begins with a phishing email designed to direct victims to a Tycoon2FA CAPTCHA page.
2.  Upon successful CAPTCHA validation, the platform steals the victim's session cookies.
3.  A JavaScript (JS) file extracts the victim's email address.
4.  The victim is redirected to a fake Microsoft 365 or Google login page, hosted on a Tycoon2FA domain.
5.  The victim's credentials are proxied to a legitimate Microsoft 365 cloud account through an obfuscated JS file.
6.  Using the stolen cookies and credentials, the attacker authenticates to the victim's cloud environment.
7.  Once authenticated, the attacker gains access to the victim's email and other cloud resources.
8.  The ultimate objective is to compromise the victim's email account, likely for data theft or further phishing campaigns.

## Impact

Tycoon2FA's operations began in 2023, and by mid-2025, the platform was responsible for 62% of all phishing attempts blocked by Microsoft. The platform purportedly generated over 30 million malicious emails in a single month. A successful attack can result in complete compromise of the victim's email account, leading to potential data exfiltration, business email compromise (BEC), and further propagation of phishing campaigns using the compromised account. The takedown initially reduced campaign activity to 25% of pre-disruption levels, but activity quickly returned to normal.

## Recommendation

*   Monitor network traffic for connections to newly registered domains that mimic legitimate Microsoft 365 or Google login pages to detect potential Tycoon2FA domains, as mentioned in the IOC table.
*   Deploy the "Detect Tycoon2FA PhaaS Redirection" Sigma rule to identify potential phishing attempts leading to the Tycoon2FA platform.
*   Enable logging of JavaScript execution within web browsers to facilitate detection of malicious scripts used for credential harvesting and session cookie theft, which can be used to further enhance the "Detect Tycoon2FA PhaaS Cookie Theft" Sigma rule.
