---
title: Tycoon2FA Phishing Kit Targets Microsoft 365 Accounts with Device-Code Phishing
slug: 2026-05-tycoon2fa-device-code-phishing
description: The Tycoon2FA phishing kit now supports device-code phishing attacks targeting Microsoft 365 accounts, abusing Trustifi click-tracking URLs, redirecting victims through Cloudflare Workers to a fake Microsoft CAPTCHA page, tricking them into entering a device code, and granting attackers OAuth tokens and access to their Microsoft 365 accounts.
date: "2026-05-17T14:44:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - device-code phishing
  - microsoft 365
  - oauth
  - tycoon2fa
vendors:
  - Microsoft
  - Trustifi
  - Cloudflare
products:
  - Microsoft 365
  - Trustifi
  - Cloudflare Workers
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.bleepingcomputer.com/news/security/tycoon2fa-hijacks-microsoft-365-accounts-via-device-code-phishing/
rules:
  - title: Detect Device Code Phishing Redirection via Trustifi
    description: Detects a redirection from a Trustifi click-tracking URL to the Microsoft device login page, potentially indicating a device code phishing attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect Microsoft Device Login Page Access
    description: Detects access to the Microsoft device login page (microsoft.com/devicelogin) from a suspicious process.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Tycoon2FA phishing kit has been updated to include device-code phishing capabilities, allowing attackers to compromise Microsoft 365 accounts. Despite a law enforcement disruption in March 2026, the Tycoon2FA platform has been rebuilt and is back to normal activity levels. Observed in a campaign in late April 2026, the kit now leverages OAuth 2.0 device authorization grant flows. This new technique involves tricking users into entering a code on a legitimate Microsoft login page, which in turn authorizes a rogue device controlled by the attacker. The kit also includes extensive anti-analysis measures to evade detection, blocking security vendors, VPNs, sandboxes, and AI crawlers, with its blocklist containing 230 vendor names and constantly being updated.

## Attack Chain

1. The victim receives a phishing email containing a Trustifi click-tracking URL, often themed as an invoice.
2. The victim clicks the Trustifi URL, which redirects through Trustifi's infrastructure.
3. The traffic is further redirected through Cloudflare Workers.
4. Multiple layers of obfuscated JavaScript are executed in the victim's browser.
5. The victim is presented with a fake Microsoft CAPTCHA page.
6. The phishing page retrieves a Microsoft OAuth device code from the attacker's backend.
7. The victim is instructed to copy and paste the device code to `microsoft.com/devicelogin`.
8. The victim completes multi-factor authentication (MFA) on their end.
9. Microsoft issues OAuth access and refresh tokens to the attacker-controlled device, granting unauthorized access to the victim's Microsoft 365 account.

## Impact

Successful device-code phishing attacks using the Tycoon2FA kit allow attackers to gain unrestricted access to the victim's Microsoft 365 data and services, including email, calendar, and cloud file storage. Push Security reported a 37x increase in device code phishing attacks this year, highlighting the growing threat. The compromised accounts can be used for data exfiltration, business email compromise (BEC), or further lateral movement within the organization.

## Recommendation

*   Disable the OAuth device code flow when not needed, as recommended by eSentire, to prevent this attack vector.
*   Restrict OAuth consent permissions and require admin approval for third-party apps, as recommended by eSentire, to limit the impact of compromised accounts.
*   Enable Continuous Access Evaluation (CAE) and enforce compliant device access policies, as recommended by eSentire, to detect and mitigate unauthorized access.
*   Monitor Entra logs for deviceCode authentication, Microsoft Authentication Broker usage, and Node.js user agents, as recommended by eSentire, to identify potential device-code phishing attacks.
*   Block access to `microsoft.com/devicelogin` from untrusted networks or devices, as referenced in the Attack Chain, to prevent users from entering device codes on potentially malicious sites.
*   Implement detections for redirections originating from Trustifi click-tracking URLs to suspicious Microsoft login pages.
