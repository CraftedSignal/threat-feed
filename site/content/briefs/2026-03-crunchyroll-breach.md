---
title: Crunchyroll Data Breach via Telus Supply Chain Compromise
slug: 2026-03-crunchyroll-breach
description: Crunchyroll suffered a data breach after a Telus employee was phished, leading to Okta credential theft and exfiltration of 100GB of customer data.
date: "2026-03-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - data-breach
  - credential-theft
  - phishing
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://x.com/IntCyberDigest/status/2035864555805413448
  - https://www.linkedin.com/feed/update/urn:li:activity:7441656561325924352/
iocs:
  - type: email
    value: spoofed phishing email
ioc_counts:
  email: 1
rules:
  - title: Detect Anomalous Okta Login
    description: Detects Okta logins from unusual locations or IPs after a phishing attack and credential theft
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - okta
  - title: Detect Potential Data Exfiltration via Network Traffic
    description: Detects large outbound network traffic indicative of data exfiltration
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 23, 2026, a data breach was reported at Crunchyroll, stemming from a compromise of their outsourcing partner, Telus, in India. The attackers successfully gained access to Crunchyroll's environment after a Telus employee was targeted with a spoofed phishing email. This email delivered malware that stole the employee's Okta credentials, granting the attacker a foothold into Crunchyroll's systems. The breach resulted in the exfiltration of approximately 100 GB of sensitive customer analytics and ticketing data. The threat actor had unauthorized access for a duration of 24 hours before the compromised credentials were revoked. This incident highlights the risks associated with supply chain vulnerabilities and the importance of robust security measures across all partner organizations.

## Attack Chain

1. **Initial Access:** A Telus employee received a spoofed phishing email containing malware. (T1566)
2. **Malware Deployment:** The employee interacted with the phishing email, leading to the deployment of an infostealer on their machine.
3. **Credential Theft:** The malware captured the employee's Okta credentials. (TA0006)
4. **Authentication:** The attacker used the stolen Okta credentials to authenticate into Crunchyroll's environment.
5. **Data Access:** Upon successful authentication, the attacker gained access to customer analytics and ticketing data.
6. **Data Exfiltration:** The attacker exfiltrated approximately 100 GB of data, including PII such as email addresses and IP addresses. (TA0010)
7. **Lateral Movement (Likely):** While not explicitly stated, the attacker likely performed some level of lateral movement within the Crunchyroll environment to access the data.
8. **Objective Achieved:** The attacker successfully exfiltrated sensitive customer data.

## Impact

The Crunchyroll data breach resulted in the exfiltration of 100 GB of customer analytics and ticketing data. This included personally identifiable information (PII) such as email addresses and IP addresses. The exposure of this data could lead to identity theft, phishing attacks targeting Crunchyroll customers, and potential financial fraud. The breach also damages Crunchyroll's reputation and erodes customer trust. The incident underscores the critical need for robust security measures across the entire supply chain to protect sensitive customer data.

## Recommendation

*   Implement and enforce strict email security policies to prevent phishing attacks, focusing on employee training to recognize spoofed emails (T1566).
*   Deploy endpoint detection and response (EDR) solutions on all employee machines to detect and prevent malware deployment (TA0005).
*   Monitor Okta authentication logs for suspicious login activity, such as logins from unusual locations or at unusual times (TA0006).
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with access to sensitive data, to mitigate the impact of credential theft (TA0006).
*   Conduct regular security audits of all third-party vendors and partners to ensure they meet the required security standards (TA0011).
*   Deploy the Sigma rule to detect the use of stolen Okta credentials based on anomalous login patterns.
