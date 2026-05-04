---
title: Multi-Stage 'Code of Conduct' Phishing Campaign Leads to AiTM Token Compromise
slug: 2026-05-aitm-phishing
description: A widespread phishing campaign utilized 'code of conduct' lures, a multi-step attack chain, and legitimate email services to distribute authenticated messages from attacker-controlled domains, ultimately leading to adversary-in-the-middle (AiTM) token compromise, primarily targeting US-based organizations.
date: "2026-05-04T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - credential-theft
  - AiTM
  - token-compromise
vendors:
  - Microsoft
  - Cloudflare
  - Paubox
products:
  - Microsoft Defender for Office 365
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/
iocs:
  - type: domain
    value: acceptable-use-policy-calendly.de
  - type: domain
    value: compliance-protectionoutlook.de
ioc_counts:
  domain: 2
rules:
  - title: Detect Suspicious PDF Opening via Uncommon Applications
    description: Detects PDF files being opened by applications that are not commonly associated with PDF viewing, which could indicate malicious execution.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
  - title: Detect Access to Known Phishing Landing Pages
    description: Detects network connections to known attacker-controlled domains used in the AiTM phishing campaign.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - initial_access
    techniques:
      - T1566.001
      - T1568
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Between April 14 and 16, 2026, Microsoft Defender Research observed a sophisticated, large-scale phishing campaign targeting over 35,000 users across more than 13,000 organizations in 26 countries, predominantly in the United States (92%). The campaign, which did not focus on a single vertical, impacted a range of industries, with Healthcare & life sciences (19%), Financial services (18%), Professional services (11%), and Technology & software (11%) being the most affected. Attackers employed code of conduct-themed lures delivered via emails that appeared as internal compliance or regulatory communications. The campaign utilized a multi-step attack chain, including CAPTCHA challenges and intermediate staging pages, to reinforce legitimacy and filter out automated defenses, ultimately leading to an adversary-in-the-middle (AiTM) phishing flow.

## Attack Chain

1.  The attack begins with phishing emails posing as internal compliance communications, using subjects like "Internal case log issued under conduct policy".
2.  The emails contain a PDF attachment (e.g., "Awareness Case Log File – Tuesday 14th, April 2026.pdf") that claims a "code of conduct review" has been initiated.
3.  Recipients are instructed to click a “Review Case Materials” link within the PDF.
4.  Clicking the link redirects the user to one of the attacker-controlled domains (e.g., acceptable-use-policy-calendly[.]de).
5.  The landing page displays a Cloudflare CAPTCHA to validate the user and impede automated analysis.
6.  After CAPTCHA completion, the user is redirected to an intermediate site that informs them the requested documentation is encrypted and requires account authentication.
7.  The user is presented with a legitimate-looking sign-in experience, part of an AiTM phishing flow.
8.  The attackers proxy the authentication session in real time and capture authentication tokens, granting immediate account access.

## Impact

This campaign resulted in the compromise of authentication tokens, enabling attackers to gain unauthorized access to user accounts and bypass multifactor authentication. With more than 35,000 users targeted across over 13,000 organizations, the potential for widespread data breaches, financial fraud, and further malicious activities is significant. The targeting of sectors like Healthcare and Financial Services indicates a focus on high-value targets with sensitive data.

## Recommendation

*   Educate users about phishing lures, especially those using social engineering tactics and enterprise-style HTML templates.
*   Deploy the Sigma rule "Detect Suspicious PDF Opening via Uncommon Applications" to identify unusual PDF execution paths, based on the 'file_event' log source.
*   Configure email security settings in Microsoft Defender for Office 365 to filter out phishing emails effectively.
*   Enable network protection to leverage SmartScreen as a host-based web proxy.
*   Block access to the attacker-controlled domains, such as acceptable-use-policy-calendly[.]de, at the DNS resolver level.
