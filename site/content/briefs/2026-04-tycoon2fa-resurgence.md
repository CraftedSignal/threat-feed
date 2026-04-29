---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, enabling MFA bypass and email account compromise, has rebounded to pre-takedown activity levels, maintaining consistent tactics, techniques, and procedures (TTPs) after a law enforcement disruption.
date: "2026-03-28T14:22:14Z"
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
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Tycoon2FA Landing Page Redirection
    description: Detects redirects to potential Tycoon2FA landing pages from phishing emails.
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
  - title: Detect Email Address Extraction via JavaScript
    description: Detects JavaScript files attempting to extract email addresses, a TTP used by Tycoon2FA.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

On March 4, 2026, Europol disrupted Tycoon2FA, a subscription-based PhaaS platform used to bypass multifactor authentication (MFA) and compromise email accounts. The takedown involved seizing 330 domains. Despite this disruption, CrowdStrike observed a temporary decrease in Tycoon2FA activity, but it has since returned to pre-disruption levels, indicating the actors behind the platform remain active and adaptive. The platform began operations in 2023 and gained prominence, being responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025, generating over 30 million malicious emails in a single month. Defenders must maintain vigilance and continuously monitor for Tycoon2FA activity.

## Attack Chain

1.  Victims receive phishing emails designed to lure them to malicious websites.
2.  Victims are directed to Tycoon2FA CAPTCHA pages to appear legitimate.
3.  Upon CAPTCHA validation, a JavaScript (JS) file extracts the victim's email address.
4.  The JS file populates fake Microsoft 365 or Google login pages hosted on a Tycoon2FA domain.
5.  Victims enter their credentials into the fake login pages.
6.  An obfuscated JavaScript file proxies victims' credentials to a legitimate Microsoft 365 cloud account.
7.  The platform steals victims’ session cookies.
8.  Attackers authenticate to the victim’s cloud environment using the stolen cookies and credentials, gaining unauthorized access.

## Impact

The resurgence of Tycoon2FA demonstrates the resilience of PhaaS platforms. Tycoon2FA was responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025 and reportedly generated more than 30 million malicious emails in a single month. Successful attacks lead to unauthorized access to sensitive cloud environments, potentially resulting in data breaches, financial losses, and reputational damage. The persistence of Tycoon2FA after the takedown highlights the need for continuous monitoring and improved detection capabilities.

## Recommendation

*   Monitor email traffic for patterns associated with phishing campaigns that redirect to suspicious CAPTCHA pages, using network connection and process creation logs to correlate activity.
*   Deploy the Sigma rule "Detect Tycoon2FA Landing Page Redirection" to identify potential phishing attempts redirecting to Tycoon2FA infrastructure.
*   Inspect network traffic for connections to domains associated with Tycoon2FA (domain IOCs) using network connection logs and block these domains at the firewall or DNS resolver.
*   Enhance monitoring for unusual logins and session activity within cloud environments after validating CAPTCHA, leveraging cloud audit logs and identity management systems.
