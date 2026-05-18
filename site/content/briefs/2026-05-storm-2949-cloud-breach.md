---
title: Storm-2949 Abuses SSPR for Cloud-Wide Data Exfiltration
slug: 2026-05-storm-2949-cloud-breach
description: Storm-2949 compromised cloud identities through social engineering and abused the Self-Service Password Reset (SSPR) process to bypass MFA and gain persistent access, enabling lateral movement and data exfiltration from Microsoft 365 and Azure environments.
date: "2026-05-18T23:34:36Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-2949
tags:
  - cloud-security
  - credential-access
  - data-exfiltration
  - social-engineering
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft 365
  - Microsoft Authenticator
  - Microsoft Azure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/
rules:
  - title: Detect SSPR Abuse via Authentication Method Changes
    description: Detects potential abuse of Self-Service Password Reset (SSPR) by monitoring changes to authentication methods (e.g., phone numbers, email addresses) immediately after a password reset.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1566.001
    data_sources:
      - authentication
      - azure
  - title: Detect Microsoft Graph API Directory Enumeration
    description: Detects suspicious enumeration of users and applications within Microsoft Entra ID using the Microsoft Graph API.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.004
    data_sources:
      - webserver
rules_count: 2
---

Storm-2949 conducted a multi-layered attack targeting cloud infrastructure by exploiting compromised identities rather than relying on traditional malware. Starting in May 2026, the actor targeted specific users through social engineering, abusing Microsoft's Self-Service Password Reset (SSPR) to bypass MFA and gain persistent access to Microsoft Entra ID. Once inside, they moved laterally through the victim's Microsoft 365 applications, file-hosting services, and Azure-hosted production environments, exfiltrating sensitive data. This campaign highlights the increasing focus of threat actors on cloud identities and control plane access, using legitimate administrative features for malicious purposes. The attack leveraged the Microsoft Graph API for directory discovery, enumerating users and applications within the tenant to identify high-value targets.

## Attack Chain

1. **Initial Access via Social Engineering:** Storm-2949 initiates the SSPR process for targeted users, then uses social engineering (e.g., impersonating IT support) to trick them into approving MFA prompts.
2. **MFA Bypass:** Once the user approves the prompts, the attacker resets the password and removes existing authentication methods (phone numbers, email addresses, Microsoft Authenticator registrations).
3. **Persistence via New MFA Enrollment:** The attacker re-enables MFA and registers a new authentication method on their own device, granting themselves persistent access.
4. **Directory Discovery:** Using compromised credentials, the attacker conducts directory discovery using Microsoft Graph API to enumerate users and applications within the tenant.
5. **Privilege Escalation:** The attacker identifies privileged accounts to target for further compromise.
6. **Lateral Movement:** Leveraging control-plane access, the actor moves laterally across cloud and endpoint environments.
7. **Access Cloud Resources:** The attacker accesses sensitive cloud resources such as Key Vaults and storage accounts.
8. **Data Exfiltration:** The actor exfiltrates sensitive data from Microsoft 365 applications, file-hosting services, and Azure-hosted production environments.

## Impact

The Storm-2949 campaign resulted in the exfiltration of sensitive data from multiple areas of the victim organization's cloud infrastructure, including Microsoft 365 applications and Azure-hosted environments. The attackers specifically targeted high-value assets, including those within SaaS, PaaS, and IaaS layers. The compromise of IT personnel and senior leadership suggests significant potential for widespread damage. The number of affected users and the total volume of exfiltrated data are not specified in the report.

## Recommendation

*   Implement robust MFA policies and educate users about social engineering tactics targeting SSPR. Deploy the rule `Detect SSPR Abuse via Authentication Method Changes` to identify potential MFA bypass attempts.
*   Monitor Microsoft Graph API usage for unusual enumeration activities. Deploy the rule `Detect Microsoft Graph API Directory Enumeration` to identify suspicious user and application enumeration patterns.
*   Review and harden Azure role-based access control (RBAC) policies to limit lateral movement.
*   Implement behavior-based detections across endpoints, cloud environments, and identities, like those provided by Microsoft Defender XDR.
*   Regularly review and audit user accounts, especially those with elevated privileges, for any unauthorized changes to authentication methods or permissions.
