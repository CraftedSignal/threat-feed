---
brief_id: brief-2026-03-28-tycoon2fa-resurgence
event_id: brief-2026-03-28-tycoon2fa-resurgence
revision: 2
activity_at: "2026-03-28T09:37:33Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:5186379ba354ee0fc02a97dc6d96b8f2954b4dc2d96b8afef2d778ddbb4a917c
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-03-28-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, which enables cybercriminals to bypass multi-factor authentication (MFA) to compromise email accounts, has resumed campaign activity to pre-disruption levels after a law enforcement takedown.
date: "2026-03-28T09:37:33Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
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
  - title: Detect Tycoon2FA Fake Login Page Javascript Credential Harvesting
    description: Detects suspicious JavaScript activity associated with credential harvesting on fake Microsoft 365 or Google login pages.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect Tycoon2FA Cookie Theft After CAPTCHA Validation
    description: Detects potential cookie theft following CAPTCHA validation, indicating a possible Tycoon2FA attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 4, 2026, Europol announced the disruption of Tycoon2FA, a subscription-based PhaaS platform used to bypass MFA and compromise email accounts. The takedown involved seizing 330 domains. Despite this disruption, CrowdStrike observed a short-term decrease in Tycoon2FA activity followed by a return to pre-disruption levels. The actors behind Tycoon2FA have not changed their tactics, techniques, and procedures (TTPs). This suggests a high level of adaptability and persistence, requiring defenders to maintain vigilance. Tycoon2FA was responsible for 62% of phishing attempts blocked by Microsoft in mid-2025, generating over 30 million malicious emails in a single month. The platform began operations in 2023.

## Attack Chain

1.  Victims receive phishing emails directing them to Tycoon2FA CAPTCHA pages.
2.  Upon CAPTCHA validation, the platform steals the victim's session cookies.
3.  A JavaScript (JS) file extracts the victim's email address.
4.  The victim is presented with a fake Microsoft 365 or Google login page hosted on a Tycoon2FA domain.
5.  The victim enters their credentials, which are then proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
6.  The attacker authenticates to the victim's cloud environment using the stolen cookies and credentials.
7.  The attacker gains access to the victim's email and other cloud services.

## Impact

The Tycoon2FA platform has facilitated widespread email account compromise and cloud service breaches. In mid-2025, the platform was responsible for 62% of all phishing attempts blocked by Microsoft, which equated to over 30 million malicious emails in a single month. Successful attacks can lead to data theft, financial fraud, and further compromise of internal systems. Despite law enforcement actions, the platform's rapid resurgence indicates its operators are highly resilient and capable of quickly restoring their infrastructure.

## Recommendation

*   Monitor network traffic for connections to known Tycoon2FA domains identified in the IOC table to detect ongoing phishing campaigns.
*   Implement the provided Sigma rule to detect suspicious JavaScript activity associated with credential harvesting from fake login pages, and tune the rule for your environment.
*   Review and enhance MFA implementation across all cloud services, as Tycoon2FA is designed to bypass standard MFA protocols.
*   Implement the provided Sigma rule to detect cookie theft attempts, focusing on events where cookies are exfiltrated after CAPTCHA validation.
*   Educate users about phishing tactics, including the use of CAPTCHA pages and fake login portals, to reduce susceptibility to Tycoon2FA campaigns.
