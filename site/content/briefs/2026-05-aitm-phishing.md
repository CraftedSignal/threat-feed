---
title: Sophisticated AitM Phishing Campaign Targeting US Organizations
slug: 2026-05-aitm-phishing
description: A sophisticated phishing campaign targeting US organizations uses a 'code of conduct review' theme to lure victims to a malicious website, employing adversary-in-the-middle (AitM) techniques to capture authentication tokens and gain account access.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - aitm
  - credential-access
  - initial-access
vendors:
  - Microsoft
  - Cloudflare
products:
  - Microsoft account
  - Cloudflare CAPTCHA
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
  - https://www.securityweek.com/microsoft-warns-of-sophisticated-phishing-campaign-targeting-us-organizations/
rules:
  - title: Detect Phishing Email Redirection to CAPTCHA
    description: Detects potential phishing attempts where a link in an email redirects to a CAPTCHA challenge, often used as a gating mechanism in sophisticated phishing campaigns.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect Microsoft Account AitM Phishing Login Page
    description: Detects access to Microsoft login pages immediately after CAPTCHA verification, potentially indicating AitM phishing activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Microsoft has warned of a sophisticated phishing campaign primarily targeting US organizations, with 92% of observed attempts focused within the United States. The campaign, active between April 14 and 16, 2026, involved over 35,000 phishing attempts across approximately 13,000 organizations spanning 26 countries. The phishing emails masquerade as internal regulatory or compliance messages, using display names like ‘Team Conduct Report’ and subject lines such as ‘Reminder: employer opened a non-compliance case log.’ The targeted sectors include healthcare, life sciences, financial services, professional services, and technology/software. The attackers are leveraging a legitimate email delivery service and likely attacker-controlled domains to send the malicious emails. This campaign is significant because it employs AitM phishing, bypassing traditional MFA protections.

## Attack Chain

1.  The victim receives a phishing email purporting to be an internal regulatory or compliance message, with subjects related to conduct reports or non-compliance.
2.  The email instructs the recipient to open a personalized attachment (PDF document) to review case materials.
3.  The attachment contains a link, such as "Review Case Materials," that the user is directed to click.
4.  Clicking the link redirects the user to a Cloudflare CAPTCHA page, likely to thwart automated analysis.
5.  The user is then directed to a page indicating that documents need review and signature.
6.  The victim is prompted to enter their email address, followed by a second CAPTCHA page.
7.  After successful verification, the user is asked to sign in to their Microsoft account.
8.  This final step uses AitM phishing, where the attacker proxies the session in real-time to capture authentication tokens and gain immediate access to the targeted account.

## Impact

This phishing campaign can lead to unauthorized access to Microsoft accounts, potentially enabling data theft, business email compromise (BEC), and further malicious activities within the compromised organization. With 35,000 attempts observed in a short period, the potential scale of compromise is significant. The targeting of healthcare, financial services, and technology sectors suggests a focus on high-value targets. Successful attacks can result in financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Deploy the "Detect Phishing Email Redirection to CAPTCHA" Sigma rule to identify potential phishing attempts leading to CAPTCHA challenges (rules).
*   Implement the "Detect Microsoft Account AitM Phishing Login Page" Sigma rule to detect access to Microsoft login pages after CAPTCHA verification, indicating potential AitM activity (rules).
*   Review email gateway configurations to ensure robust filtering of emails with subjects related to compliance or conduct reports (overview).
*   Educate users about the risks of AitM phishing and the importance of verifying the authenticity of login pages, especially after CAPTCHA challenges (overview).
*   Leverage Microsoft's threat-hunting queries and indicators of compromise (IoCs) to proactively search for related activity within your environment (overview).
