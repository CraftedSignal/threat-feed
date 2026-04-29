---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, disrupted in March 2026, has resurged with cloud compromise active remediations returning to early 2026 levels, continuing to bypass MFA and compromise email accounts through phishing campaigns.
date: "2026-03-29T06:44:52Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - credential-theft
  - mfa-bypass
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
  - title: Detect Tycoon2FA Fake Login Page Redirection
    description: Detects redirections to fake Microsoft 365 or Google login pages hosted on suspicious domains.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect Tycoon2FA Cookie Theft via CAPTCHA
    description: Detects suspicious network connections following interaction with a CAPTCHA page, indicating potential cookie theft.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Tycoon2FA is a subscription-based Phishing-as-a-Service (PhaaS) platform that enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. The platform was disrupted on March 4, 2026, by Europol and law enforcement in six countries, seizing 330 domains. Before the takedown, in mid-2025, the platform was responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. Despite the disruption, CrowdStrike Falcon Complete Next-Gen MDR and Counter Adversary Operations teams observed a short-term decrease in activity followed by a return to pre-disruption levels, indicating the actors behind Tycoon2FA remain active and are adapting their TTPs, warranting continued vigilance.

## Attack Chain

1.  Initial Access: Victims receive phishing emails that redirect them to Tycoon2FA CAPTCHA pages.
2.  Credential Harvesting: Upon CAPTCHA validation, victims' session cookies are stolen.
3.  Email Address Extraction: A JavaScript (JS) file is used to extract victims’ email addresses.
4.  Fake Login Pages: Victims are presented with fake Microsoft 365 or Google login pages hosted on a Tycoon2FA domain.
5.  Credential Proxying: The victim's credentials are proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
6.  Authentication: The attacker authenticates to the victim's cloud environment using the stolen cookies and credentials.
7.  Account Compromise: Successful authentication leads to the compromise of the victim's Microsoft 365 or Google account.

## Impact

The Tycoon2FA platform was responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025, generating more than 30 million malicious emails in a single month. A successful attack can lead to complete account compromise, enabling attackers to access sensitive information, conduct further phishing campaigns, and potentially pivot to other systems. The resurgence of Tycoon2FA after the takedown indicates the platform remains a significant threat.

## Recommendation

*   Deploy the "Detect Tycoon2FA Fake Login Page Redirection" Sigma rule to identify potential phishing attempts leading to Tycoon2FA infrastructure.
*   Deploy the "Detect Tycoon2FA Cookie Theft via CAPTCHA" Sigma rule to detect potential cookie theft attempts after CAPTCHA validation.
*   Monitor network traffic for connections to known and newly identified Tycoon2FA domains, as mentioned in the overview section.
*   Educate users on identifying phishing emails and avoiding interaction with suspicious CAPTCHA pages, referencing the attack chain described in this brief.
