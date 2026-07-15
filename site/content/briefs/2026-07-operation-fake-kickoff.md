---
title: 'Operation Fake KickOff: Attackers Abuse Recruiters and SaaS to Harvest Work Credentials'
slug: 2026-07-operation-fake-kickoff
description: O-UNC-038 is conducting a multi-stage Adversary-in-the-Middle (AiTM) phishing operation that abuses legitimate SaaS platforms and recruiter identities to steal corporate Google Workspace credentials and bypass multi-factor authentication.
date: "2026-07-15T20:50:29Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - O-UNC-038
tags:
  - phishing
  - credential-theft
  - aitm
  - social-engineering
  - mfa-bypass
  - saas-abuse
  - google-workspace
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The adversaries weaponized legitimate marketing and email-delivery platforms such as Salesforce, SendGrid, and Zoho to distribute email lures leading victims to the phishing landing pages.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Victims were forwarded to landing pages tailored to mimic a standard Calendly interview interface, using the identity of real recruiters associated with impersonated organizations.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: designed to harvest corporate Google Workspace credentials, live session tokens in real time and bypass standard multi-factor authentication (MFA) mechanisms.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: designed to harvest corporate Google Workspace credentials, live session tokens in real time and bypass standard multi-factor authentication (MFA) mechanisms.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Forge Web Credentials
    evidence: The toolkit also had four scripts dedicated to harvest MFA authentication codes delivered via email, short message service (SMS), the Google Authenticator app and Google prompt notification.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The phishing pages were designed with the React framework and had AiTM capabilities... Analysis of the phishing page revealed a set of instructions to perform the Browser-in-the-Box (BitB) technique
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: captures additional victim telemetry such as the client's IP address and localized geographic data via the third-party ipwho.is service
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Stolen credentials were forwarded to C2 servers on Render cloud hosting infrastructure
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Stolen victim data was then exfiltrated downstream to Telegram.
    confidence_band: high
references:
  - https://www.intel471.com/blog/operation-fake-kickoff-attackers-abuse-recruiters-and-saas-to-harvest-work-credentials
iocs:
  - type: domain
    value: onrender.com
ioc_counts:
  domain: 1
rules:
  - title: Detect DNS Queries to Render Cloud Platform C2 (Operation Fake KickOff)
    description: Detects DNS queries to domains associated with the Render cloud platform, which Operation Fake KickOff uses for Command and Control (C2) infrastructure to exfiltrate stolen credentials and session data.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1102.002
    data_sources:
      - dns_query
      - windows
  - title: Detect Network Connections to Render Cloud Platform C2 (Operation Fake KickOff)
    description: Detects outbound network connections from internal hosts to domains on the Render cloud platform, identified as C2 infrastructure for Operation Fake KickOff to exfiltrate stolen data.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1102.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Intel 471 has investigated "Operation Fake KickOff," an ongoing, multi-stage phishing campaign attributed to O-UNC-038, which has been active since at least April 2025. This operation systematically abuses legitimate software-as-a-service (SaaS) platforms like Salesforce, SendGrid, and Zoho for email distribution to orchestrate corporate credential theft. Attackers impersonate real recruiters from major global brands across 15 industry verticals, primarily human resources consulting, to lure victims to deceptive, corporate-themed interview-scheduling interfaces. An adversary-in-the-middle (AiTM) toolkit, leveraging the Browser-in-the-Box (BitB) technique, is then deployed to harvest corporate Google Workspace credentials and live session tokens in real time, effectively bypassing standard multi-factor authentication (MFA) mechanisms. The campaign has identified 232 dedicated phishing domains and 80 command-and-control (C2) servers, with stolen data exfiltrated to Render cloud hosting infrastructure and subsequently to Telegram bots.

## Attack Chain

1. Attackers use legitimate SaaS marketing and email-delivery platforms such as Salesforce, SendGrid, and Zoho to distribute email lures.
2. Email lures impersonate real recruiters from well-known organizations across various industries, often using typosquatted domains like `fifahr-careers.com` or `adidas-hiring.com`.
3. Victims click on links within these emails, directing them to deceptive landing pages designed to mimic standard interview-scheduling interfaces, such as Calendly.
4. The phishing landing page performs email validation, blocking standard personal email providers and compelling victims to enter corporate email addresses.
5. Upon corporate email submission, the page initiates an Adversary-in-the-Middle (AiTM) attack, presenting a visually identical Google sign-in replica page via the Browser-in-the-Box (BitB) technique within the current tab to harvest credentials.
6. As victims enter their corporate Google Workspace credentials, the AiTM toolkit orchestrates MFA bypasses by dynamically prompting for various second-factor challenges, including email codes, TOTP from Google Authenticator, SMS codes, and Google prompt notifications.
7. The attackers capture corporate Google Workspace credentials and live session tokens in real-time as they are entered and authenticated.
8. Stolen credentials and session data are transmitted via HTTP POST requests to C2 servers hosted primarily on the Render cloud platform (`onrender.com`) and then exfiltrated downstream to Telegram bots.

## Impact

This operation has resulted in the theft of corporate Google Workspace login credentials and live session tokens, effectively bypassing multi-factor authentication. Organizations across 15 distinct industry verticals have been impersonated, with human resources consulting firms accounting for approximately 54% of observed phishing infrastructure. The campaign has been active since April 2025 and continues to successfully deploy live phishing pages and harvest corporate access, leading to unauthorized access to enterprise cloud environments. The broad impersonation and abuse of legitimate SaaS platforms increase the success rate of the attacks, making them difficult for targeted users to discern.

## Recommendation

* Deploy Sigma rules detecting suspicious DNS queries to `onrender.com`, as this domain is used for C2 infrastructure.
* Implement Sigma rules identifying suspicious network connections to `onrender.com` from corporate endpoints.
* Enhance email gateway and proxy logs monitoring for phishing attempts originating from legitimate SaaS platforms (e.g., Salesforce, SendGrid, Zoho) but redirecting to external, typosquatted, or unknown domains.
* Conduct regular security awareness training emphasizing the risks of sophisticated phishing, recruiter impersonation, and the visual cues of legitimate OAuth pop-ups versus in-tab login redirects.
* Implement FIDO2 or other phishing-resistant MFA solutions where feasible to mitigate the risk of AiTM attacks and session token theft.
