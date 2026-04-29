---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service platform, used to bypass MFA and compromise email accounts, has demonstrated resilience following a law enforcement takedown, with campaign activity returning to pre-disruption levels and TTPs remaining consistent.
date: "2026-03-30T06:20:50Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - credential-theft
  - phishing-as-a-service
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Tycoon2FA Phishing Landing Page Redirection
    description: Detects redirects to potential Tycoon2FA phishing landing pages by monitoring network connections for specific domain patterns after an initial HTTP request.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Tycoon2FA competitor domain RaccoonO365
    description: Detects redirects to potential RaccoonO365 phishing landing pages by monitoring network connections for specific domain patterns after an initial HTTP request.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 4, 2026, Europol disrupted Tycoon2FA, a Phishing-as-a-Service (PhaaS) platform enabling cybercriminals to bypass multifactor authentication (MFA). This takedown involved seizing 330 domains that constituted the platform’s core infrastructure. Despite this disruption, CrowdStrike Falcon Complete Next-Gen MDR and Counter Adversary Operations teams have observed a resurgence in Tycoon2FA campaign activity. While there was a short-term decrease in activity immediately following the takedown, the volume of cloud compromises has since returned to levels observed prior to the disruption. The platform's tactics, techniques, and procedures (TTPs) have remained consistent, suggesting the actors behind Tycoon2FA are likely to remain active. Tycoon2FA began operations in 2023 and by mid-2025, the platform was reportedly responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. The platform's primary competitor, RaccoonO365, was targeted in September 2025.

## Attack Chain

1.  Victims receive phishing emails designed to direct them to Tycoon2FA CAPTCHA pages.
2.  Upon successful CAPTCHA validation, a JavaScript (JS) file is executed to extract the victim's email address.
3.  The victim is redirected to a fake Microsoft 365 or Google login page hosted on a Tycoon2FA domain.
4.  The fake login page proxies the victim's credentials to a legitimate Microsoft 365 cloud account via an obfuscated JavaScript file.
5.  Victim's session cookies are stolen upon entering credentials.
6.  The stolen cookies and credentials are used to authenticate to the victim’s cloud environment.
7.  Malicious actors gain access to the victim's email account and other cloud resources.
8.  The attacker performs follow-on activities such as data exfiltration, business email compromise, or further lateral movement.

## Impact

The Tycoon2FA platform was responsible for a significant portion of phishing attempts, accounting for 62% of all phishing attempts blocked by Microsoft in mid-2025 and generating over 30 million malicious emails in a single month. A successful attack can lead to unauthorized access to sensitive data, financial losses through business email compromise, and reputational damage. The resurgence of Tycoon2FA, even after a takedown, demonstrates the persistence of these threats and the potential for widespread impact.

## Recommendation

*   Deploy the "Detect Tycoon2FA Phishing Landing Page Redirection" Sigma rule to identify suspicious redirects to potential Tycoon2FA phishing pages based on network connection logs.
*   Monitor network traffic for connections to known PhaaS domains like "Tycoon2FA" and "RaccoonO365" as potential indicators of compromise (IOCs).
*   Implement and enforce phishing-resistant MFA solutions to mitigate the impact of credential compromise. Consider FalconID, as mentioned in the source material.
*   Conduct regular security awareness training to educate users about phishing tactics and how to identify suspicious emails and websites.
*   Enable and review cloud security logs for suspicious login activity, including logins from unusual locations or devices, to detect account compromise.
