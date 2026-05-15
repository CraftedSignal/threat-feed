---
title: UNC6671 BlackFile Vishing Extortion Campaign Targeting Microsoft 365 and Okta
slug: 2026-05-blackfile-vishing
description: UNC6671, operating under the "BlackFile" brand, conducts a sophisticated extortion campaign targeting organizations through voice phishing (vishing) and single sign-on (SSO) compromise, using adversary-in-the-middle (AiTM) techniques to bypass MFA and exfiltrate sensitive corporate data.
date: "2026-05-15T17:08:04Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UNC6671
tags:
  - vishing
  - extortion
  - aitm
  - credential-theft
  - data-exfiltration
  - sso
vendors:
  - Google
  - Microsoft
  - Okta
  - Tucows
  - Zendesk
  - Salesforce
products:
  - Microsoft 365
  - Okta
  - SharePoint
  - OneDrive
  - Zendesk
  - Salesforce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation/
  - https://cloud.google.com/blog/topics/threat-intelligence/expansion-shinyhunters-saas-data-theft
iocs:
  - type: domain
    value: enrollms[.]com
  - type: domain
    value: passkeyms[.]com
  - type: domain
    value: setupsso[.]com
  - type: ip
    value: 179.43.185.226
  - type: email
    value: victim.user@organization.com
ioc_counts:
  domain: 3
  email: 1
  ip: 1
rules:
  - title: Detect Mismatched User-Agent and Application Display Name in SharePoint Online
    description: Detects scripted data exfiltration attempts in SharePoint Online by identifying mismatches between the User-Agent and ApplicationDisplayName, indicative of automated scripts spoofing legitimate applications.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - webserver
  - title: Detect Generic User-Agent in SharePoint Online FileAccessed Events
    description: Detects file access events with generic User-Agent strings indicative of scripted access to SharePoint Online resources.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - webserver
rules_count: 2
---

UNC6671, known as "BlackFile," is engaged in an extensive extortion campaign targeting organizations using sophisticated vishing and SSO compromise techniques. Since early 2026, the group has targeted dozens of organizations across North America, Australia, and the UK. The group leverages adversary-in-the-middle (AiTM) attacks to bypass traditional security measures, including multi-factor authentication (MFA), primarily targeting Microsoft 365 and Okta environments. UNC6671 employs Python and PowerShell scripts to programmatically exfiltrate sensitive corporate data from SharePoint and OneDrive, later used for extortion. These attacks do not exploit software vulnerabilities but rely on social engineering, highlighting the need for phishing-resistant MFA.

## Attack Chain

1.  **Initial Vishing:** The attacker initiates a voice phishing (vishing) call to a target employee, often on their personal cellular phone, impersonating IT or help desk personnel.
2.  **Credential Harvesting:** The attacker directs the victim to a fake SSO login page (e.g., `<organization>.enrollms[.]com`) under the guise of a mandatory passkey migration or MFA update, capturing their username and password.
3.  **MFA Bypass (AiTM):** As the victim enters their credentials, the attacker relays them to the legitimate SSO provider, intercepting the MFA challenge (Push, SMS, or TOTP). The victim unknowingly provides the MFA code to the attacker.
4.  **Device Registration:** With successful authentication, the attacker immediately registers a new, attacker-controlled MFA device to the user's account for persistent access.
5.  **Lateral Movement:** Using the compromised SSO credentials, the attacker moves laterally across the victim's SaaS applications, focusing on Microsoft 365 and Okta environments. They access SharePoint, OneDrive, and other connected apps like Zendesk and Salesforce.
6.  **Data Discovery:** The attacker queries internal search functions within these applications, looking for sensitive data using keywords such as "confidential" and "SSN."
7.  **Programmatic Exfiltration:** The attacker utilizes Python and PowerShell scripts to automate the exfiltration of high-value data from SharePoint and OneDrive repositories. They use Microsoft Graph API or direct HTTP GET requests, often using stolen session cookies (e.g., FedAuth) to stream file content to attacker-controlled infrastructure.
8.  **Extortion:** After successfully exfiltrating sensitive data, UNC6671 threatens to leak the stolen information on their dedicated "BlackFile" data leak site (DLS) unless a ransom is paid.

## Impact

UNC6671's campaign has targeted dozens of organizations across North America, Australia, and the UK, resulting in the theft of sensitive corporate data. Successful attacks can lead to significant financial losses, reputational damage, and legal consequences due to the exposure of confidential information and personal data. The group's use of social engineering and AiTM techniques allows them to bypass traditional security controls, making them a formidable threat to organizations relying on cloud-based services.

## Recommendation

*   Deploy the Sigma rule "Detect Mismatched User-Agent and Application Display Name in SharePoint Online" to identify scripted data exfiltration attempts with spoofed ClientAppId, based on the log example in this brief.
*   Block the domains `enrollms[.]com`, `passkeyms[.]com`, and `setupsso[.]com` at the DNS resolver to prevent users from accessing credential harvesting sites.
*   Implement phishing-resistant MFA methods, as highlighted in the overview, to prevent AiTM attacks.
*   Monitor FileAccessed events in Microsoft 365 Unified Audit Logs for unusual activity, particularly those originating from non-standard infrastructure (VPNs, hosting providers) and associated with scripting engines like python-requests, per the forensic artifacts described.
