---
brief_id: brief-2026-03-30-tycoon2fa-resurgence-v3
event_id: brief-2026-03-30-tycoon2fa-resurgence-v3
revision: 2
activity_at: "2026-03-30T12:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:4e361873cec8c74159127ae2c862d5ccb553ad352617eeecae695893c96a1b50
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence Following Takedown
slug: 2026-03-30-tycoon2fa-resurgence-v3
description: The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, disrupted by Europol on March 4, 2026, has shown resilience with campaign activity returning to pre-disruption levels, employing adversary-in-the-middle (AITM) techniques to intercept authentication sessions and bypass MFA, highlighting the need for continuous vigilance and robust detection capabilities.
date: "2026-03-30T12:00:00Z"
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
  - aitm
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
  - title: Detect Tycoon2FA Redirect
    description: Detects redirects to potential Tycoon2FA phishing landing pages.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - proxy
      - windows
  - title: Detect Abnormal Authentication Using Potentially Stolen Cookies
    description: Detects authentication events using cookies from unusual locations, potentially indicating session hijacking.
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

Tycoon2FA is a subscription-based phishing-as-a-service (PhaaS) platform that allows cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts using adversary-in-the-middle (AITM) techniques. Europol conducted a technical disruption of Tycoon2FA on March 4, 2026, seizing 330 domains associated with its infrastructure. Despite this takedown, CrowdStrike Falcon Complete Next-Gen MDR and Counter Adversary Operations teams observed a short-term decrease in campaign activity followed by a return to pre-disruption levels, indicating the actors responsible are likely to remain active. In mid-2025, the platform was responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. The platform began its operations in 2023.

## Attack Chain

1.  Victims receive phishing emails designed to direct them to Tycoon2FA CAPTCHA pages.
2.  Upon CAPTCHA validation, the platform steals the victim's session cookies.
3.  A JavaScript (JS) file extracts the victim's email addresses.
4.  The platform populates fake Microsoft 365 or Google login pages hosted on a Tycoon2FA domain.
5.  An obfuscated JS file proxies the victim’s credentials to a legitimate Microsoft 365 cloud account.
6.  The attackers authenticate to the victim’s cloud environment using the stolen cookies and credentials.
7.  Attackers gain unauthorized access to the victim's email and cloud resources.

## Impact

Tycoon2FA has been responsible for a significant volume of phishing attacks, including generating more than 30 million malicious emails in a single month (mid-2025), and was responsible for 62% of all phishing attempts blocked by Microsoft. The platform allows attackers to bypass MFA, leading to compromised email accounts and potential data breaches. Despite the disruption, the platform's activity has returned to pre-disruption levels, indicating a need for continuous monitoring and mitigation strategies. Successful attacks can lead to significant financial loss, data theft, and reputational damage.

## Recommendation

*   Monitor email traffic for links to newly registered or suspicious domains used in phishing campaigns, utilizing a network connection monitoring system (e.g., firewall logs) to identify connections to domains resembling "Tycoon2FA" mentioned in the overview.
*   Implement detection rules to identify the use of stolen session cookies for authentication to cloud environments, focusing on authentication logs (e.g., Azure AD logs, Google Workspace logs).
*   Deploy the Sigma rule `Detect_Tycoon2FA_Redirect` to identify redirects to potential Tycoon2FA landing pages based on URL patterns extracted from the attack chain.
*   Monitor for JavaScript execution in web pages that attempts to extract email addresses, using a web application firewall or endpoint detection and response (EDR) solution capable of inspecting client-side scripts.
