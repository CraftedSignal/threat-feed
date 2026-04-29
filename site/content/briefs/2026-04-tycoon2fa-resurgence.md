---
title: Tycoon2FA Phishing-as-a-Service Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, which bypasses multi-factor authentication (MFA) using adversary-in-the-middle (AITM) techniques, has seen a resurgence in activity to pre-takedown levels despite a law enforcement disruption in March 2026.
date: "2026-03-28T11:00:46Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - phishing
  - credential-theft
  - MFA-bypass
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
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Credential Proxying via Suspicious Process Creation
    description: Detects suspicious process creation events where JavaScript or other scripting engines are used to proxy credentials to external domains, a technique used by Tycoon2FA.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Cookie Stealing via JavaScript
    description: Detects suspicious JavaScript activity attempting to access and exfiltrate cookie data, often associated with session hijacking.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Tycoon2FA is a subscription-based Phishing-as-a-Service (PhaaS) platform that allows cybercriminals to bypass multi-factor authentication (MFA) and compromise email accounts. The platform utilizes adversary-in-the-middle (AITM) techniques to intercept live authentication sessions. On March 4, 2026, Europol announced a technical disruption of Tycoon2FA, seizing 330 domains that formed the platform's infrastructure. Despite this takedown, CrowdStrike Falcon Complete observed a short-term decrease in campaign activity followed by a resurgence to pre-disruption levels. The platform was responsible for 62% of all phishing attempts blocked by Microsoft in mid-2025 and reportedly generated more than 30 million malicious emails in a single month. The continued activity and consistent TTPs indicate the actors behind Tycoon2FA remain a persistent threat.

## Attack Chain

1.  Victims receive phishing emails containing links to attacker-controlled domains.
2.  The links redirect victims to Tycoon2FA CAPTCHA pages to filter out automated scanners.
3.  Upon successful CAPTCHA validation, a JavaScript file extracts the victim's email address.
4.  Victims are presented with fake Microsoft 365 or Google login pages hosted on a Tycoon2FA domain.
5.  The fake login pages proxy the victim's credentials to a legitimate Microsoft 365 cloud account via an obfuscated JavaScript file, stealing their credentials.
6.  The malicious JavaScript steals victims’ session cookies.
7.  Attackers authenticate to the victim's cloud environment using the stolen credentials and session cookies, bypassing MFA.
8.  Attackers gain access to the victim's email and other cloud resources for data exfiltration or further malicious activity.

## Impact

Tycoon2FA's resurgence poses a significant threat to organizations relying on MFA for security. The platform was responsible for a large percentage of phishing attempts and a high volume of malicious emails. Successful attacks lead to compromised email accounts, data breaches, and potential further compromise of cloud resources. The platform's ability to bypass MFA makes it particularly dangerous. If attackers successfully gain access to user accounts, they can steal sensitive information, send malicious emails to other users, and compromise entire networks.

## Recommendation

*   Monitor email traffic for links to newly registered or suspicious domains, especially those mimicking Microsoft or Google login pages, to detect initial access attempts.
*   Implement detection rules for unusual JavaScript activity within web browsers, focusing on scripts that extract email addresses or proxy credentials to external sites. Use the process_creation rule below as a base.
*   Analyze network traffic for connections to known Tycoon2FA domains mentioned in threat intelligence feeds. Block connections to the Tycoon2FA domain listed in the IOC section at the network perimeter.
*   Investigate suspicious logins and account activity, especially those originating from unusual locations or devices, which could indicate successful MFA bypass. Enable and monitor cloud logs for successful logins from unusual locations.
*   Educate users about the dangers of phishing emails and how to identify them to prevent initial compromise.
*   Deploy the Sigma rule to detect credential proxying activity.
