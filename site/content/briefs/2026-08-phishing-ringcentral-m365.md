---
title: Phishing-as-a-Service Campaign Impersonating RingCentral for M365 Credential Theft
slug: 2026-08-phishing-ringcentral-m365
description: Threat actors are leveraging a phishing-as-a-service platform to conduct spearphishing attacks impersonating RingCentral, targeting Microsoft 365 credentials.
date: "2026-08-05T09:12:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Microsoft
  - RingCentral
products:
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Threat actors are utilizing a phishing-as-a-service platform to impersonate RingCentral in order to harvest user credentials for Microsoft 365 accounts.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Threat actors are utilizing a phishing-as-a-service platform to impersonate RingCentral in order to harvest user credentials for Microsoft 365 accounts.
    confidence_band: high
references:
  - https://www.bleepingcomputer.com/news/security/phishing-service-spoofs-ringcentral-to-steal-microsoft-365-accounts
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review M365 sign-in logs for anomalous login patterns linked to newly provisioned MFA devices or impossible travel.
      owner: SOC
      due: 24h
      evidence: Threat focuses on credential harvesting for M365.
  mitigation_plan:
    - priority: immediate
      action: Enforce phishing-resistant MFA across the M365 tenant.
      owner: IT Operations
      addresses: M365 Account Compromise
      evidence: Credential harvesting remains the primary objective of this threat.
---

Security researchers have identified an active phishing-as-a-service campaign that impersonates RingCentral communications to facilitate the theft of Microsoft 365 user credentials. This campaign relies on the delivery of deceptive emails that mimic legitimate RingCentral notifications, redirecting users to malicious phishing pages designed to capture authentication tokens and passwords. By utilizing a phishing-as-a-service model, threat actors are able to scale these campaigns effectively, bypassing traditional email filters by leveraging legitimate brand trust associated with RingCentral. The primary objective is the compromise of enterprise accounts, providing attackers with a foothold for lateral movement, data exfiltration, or further social engineering within the target organization. This threat is significant due to the prevalence of Microsoft 365 in enterprise environments and the difficulty of detecting high-quality brand impersonation via standard email security gateways.

## Impact

The campaign facilitates the unauthorized access to corporate Microsoft 365 accounts. Successful compromise allows attackers to gain access to sensitive internal communications, documents, and corporate data. While specific victim numbers are not disclosed, the use of a phishing-as-a-service platform indicates the threat is widespread and designed for high-volume targeting across various business sectors.

## Recommendation

* Implement and enforce phishing-resistant Multi-Factor Authentication (MFA), such as FIDO2/WebAuthn, for all Microsoft 365 accounts to mitigate credential harvesting success.
* Enable and configure Microsoft 365 Defender for Office 365 "Safe Links" and "Safe Attachments" to detect and block malicious URLs at the time of click.
* Review and harden organizational email security policies, ensuring SPF, DKIM, and DMARC are strictly enforced for inbound mail.
* Train employees to verify the sender address and hover over links in incoming communications, specifically those referencing urgent "RingCentral" notifications.
