---
title: Tycoon2FA Phishing-as-a-Service Platform Persists After Takedown
slug: 2026-03-tycoon2fa-persistence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, used to bypass MFA and compromise email accounts, saw a temporary decrease in activity after a law enforcement takedown, but cloud compromises have since returned to pre-disruption levels with unchanged TTPs, indicating continued threat actor activity.
date: "2026-03-29T08:34:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - credential-theft
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
  - title: Detect Connection to Tycoon2FA Domain
    description: Detects connections to domains associated with the Tycoon2FA Phishing-as-a-Service platform based on domain names.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect JavaScript Email Address Extraction
    description: Detects process creation events indicative of JavaScript being used to extract email addresses, a technique used by Tycoon2FA.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 4, 2026, Europol announced a technical disruption of Tycoon2FA, a subscription-based phishing-as-a-service (PhaaS) platform enabling cybercriminals to bypass MFA and compromise email accounts. The takedown involved seizing 330 domains. Despite this disruption, CrowdStrike observed only a short-term decrease in Tycoon2FA campaign activity. The volume of cloud compromises has since returned to pre-disruption levels, and Tycoon2FA’s tactics, techniques, and procedures (TTPs) remain unchanged. This resurgence suggests that the actors behind Tycoon2FA are adaptive and persistent. Tycoon2FA began operations in 2023, and in mid-2025, it was responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. The platform also had a competitor named RaccoonO365, which law enforcement took down in September 2025.

## Attack Chain

1.  Victims receive phishing emails designed to mimic legitimate login pages.
2.  Phishing emails direct victims to Tycoon2FA CAPTCHA pages hosted on attacker-controlled domains.
3.  Upon CAPTCHA validation, victims' session cookies are stolen by the attackers.
4.  A JavaScript (JS) file extracts victims' email addresses.
5.  Victims are redirected to fake Microsoft 365 or Google login pages hosted on a Tycoon2FA domain.
6.  Victims enter their credentials into the fake login pages, which are then captured by the attackers.
7.  Stolen credentials are proxied to a legitimate Microsoft 365 cloud account via an obfuscated JS file.
8.  Attackers authenticate to the victim's cloud environment using the stolen cookies and credentials, gaining unauthorized access.

## Impact

Tycoon2FA was responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025, generating over 30 million malicious emails in a single month. Successful attacks lead to unauthorized access to victims' cloud environments, potentially resulting in data theft, business email compromise (BEC), and further malicious activities. Despite law enforcement takedowns, the platform's rapid resurgence demonstrates the resilience of PhaaS operations and their potential for significant damage.

## Recommendation

*   Monitor network traffic for connections to known phishing domains or newly registered domains, correlating with user agent strings and HTTP referrer headers common in phishing kits, to detect initial access attempts. Deploy the network_connection Sigma rule to identify suspicious connections.
*   Implement detections for suspicious JavaScript execution within browser environments attempting to steal session cookies or extract email addresses. Enable webserver and proxy logging to capture these events and deploy the process_creation Sigma rule to identify associated processes.
*   Monitor authentication logs for successful logins from unusual locations or using suspicious user agents after a user has visited a known phishing site. Analyze user authentication patterns and correlate with other security events to detect compromised accounts.
