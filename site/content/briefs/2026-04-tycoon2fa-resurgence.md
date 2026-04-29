---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA PhaaS platform, which facilitates MFA bypass and email account compromise, experienced a temporary decrease in activity following a takedown in March 2026, but campaign volumes and TTPs quickly returned to pre-disruption levels, indicating the actors behind the platform remain active and adaptive.
date: "2026-03-30T23:00:57Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - credential-theft
  - phishing-as-a-service
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
  - title: Detect Suspicious JavaScript for Cookie Extraction
    description: Detects JavaScript code potentially used for extracting session cookies after CAPTCHA validation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Proxying Credentials to Microsoft 365 via JavaScript
    description: Detects JavaScript code proxying credentials to Microsoft 365 cloud account, indicative of credential harvesting.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 4, 2026, Europol disrupted the Tycoon2FA PhaaS platform, seizing 330 domains that formed its core infrastructure. This platform, active since 2023, allows cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. In mid-2025, Tycoon2FA was reportedly responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. Despite the takedown, CrowdStrike observed only a short-term decrease in Tycoon2FA activity, with campaign volumes quickly returning to pre-disruption levels, and TTPs remaining unchanged. This indicates the actors behind the platform remain active and adaptive, warranting continued vigilance by defenders.

## Attack Chain

1.  The attack begins with a phishing email designed to lure victims to a Tycoon2FA-controlled domain.
2.  Victims are presented with a Tycoon2FA CAPTCHA page to solve, likely to filter out automated systems and add legitimacy.
3.  Upon successful CAPTCHA validation, the victim's session cookies are stolen by the attacker.
4.  The victim is then redirected to a fake Microsoft 365 or Google login page hosted on a Tycoon2FA domain, crafted to harvest credentials.
5.  The entered credentials, along with stolen cookies, are proxied to a legitimate Microsoft 365 cloud account via an obfuscated JavaScript (JS) file.
6.  Attackers authenticate to the victim’s cloud environment using the stolen session cookies and credentials.
7.  Once authenticated, the attacker gains access to the victim's email and potentially other cloud services.
8.  The attacker can then perform actions such as reading emails, sending phishing emails to other users, or exfiltrating sensitive data.

## Impact

The Tycoon2FA platform was responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025, generating over 30 million malicious emails in a single month. A successful compromise allows attackers to access sensitive data, spread phishing attacks further, and potentially cause significant financial and reputational damage to victim organizations. Even after the takedown of some infrastructure, the platform quickly resumed operation, highlighting the resilience of PhaaS operations.

## Recommendation

*   Monitor network traffic for connections to known Tycoon2FA domains (Tycoon2FA domain, RaccoonO365) at the network perimeter.
*   Implement and tune the provided Sigma rules to detect suspicious JavaScript execution and cookie theft attempts following CAPTCHA validation.
*   Educate users to identify phishing emails, especially those redirecting to unusual CAPTCHA pages or login portals.
*   Investigate any alerts of unusual logins from unexpected locations or devices based on cloud access logs.
