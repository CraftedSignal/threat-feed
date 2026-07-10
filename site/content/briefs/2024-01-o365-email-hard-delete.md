---
title: O365 Email Account Compromise via Excessive Hard Deletes
slug: 2024-01-o365-email-hard-delete
description: Compromised O365 accounts may perform excessive email hard deletes within an hour to remove evidence of malicious activity, potentially indicating account takeover.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - o365
  - email
  - account_compromise
  - data_destruction
vendors:
  - Microsoft
products:
  - Office 365
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://attack.mitre.org/techniques/T1114/
  - https://www.hhs.gov/sites/default/files/help-desk-social-engineering-sector-alert-tlpclear.pdf
  - https://intelligence.abnormalsecurity.com/attack-library/threat-actor-convincingly-impersonates-employee-requesting-direct-deposit-update-in-likely-ai-generated-attack
rules:
  - title: O365 Email Hard Delete from Unusual Location
    description: Detects O365 email hard deletes originating from unusual IP addresses, potentially indicating account compromise.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
      - initial_access
    techniques:
      - T1070.008
      - T1078
      - T1485
    data_sources:
      - Office 365 Universal Audit Log
      - o365
rules_count: 1
---

This threat brief addresses the risk of compromised Office 365 (O365) email accounts performing a high volume of email hard deletes within a short timeframe (1 hour). This activity, detected via O365 management activity logs, suggests a threat actor is attempting to cover their tracks by permanently removing emails from the 'Sent Items' or 'Recoverable Items\\Deletions' folders. This behavior is often associated with account takeover scenarios where attackers aim to eliminate evidence of phishing campaigns, data exfiltration, or other unauthorized activities. It is crucial for defenders to monitor and alert on such anomalies to identify and contain potentially compromised accounts quickly, mitigating further damage to the organization. While some legitimate user actions might trigger this alert, such activity may be misaligned with organizational best practices.

## Attack Chain

1. **Initial Access:** An attacker gains unauthorized access to an O365 email account, likely through phishing, credential stuffing, or other means.
2. **Account Reconnaissance:** The attacker explores the compromised mailbox to understand its contents and identify potentially sensitive information.
3. **Lateral Movement (Optional):** The attacker uses the compromised account to send phishing emails or malicious attachments to other users within or outside the organization.
4. **Data Exfiltration (Optional):** The attacker exfiltrates sensitive data from the compromised mailbox or uses the account to access other internal resources.
5. **Evidence Removal:** The attacker initiates a large number of "HardDelete" operations on emails within the "Sent Items" and/or "Recoverable Items\\Deletions" folders.
6. **Hard Delete Execution:** The O365 service executes the "HardDelete" operations, permanently removing the specified emails from the mailbox.
7. **Cleanup:** The attacker might modify other account settings or data to further obscure their presence.
8. **Persistence (Optional):** The attacker establishes persistence mechanisms to maintain access to the account even if the password is changed.

## Impact

A successful account compromise leading to excessive email hard deletes can have several significant impacts:

*   **Loss of Evidence:** Critical forensic evidence related to the attack is permanently deleted, hindering investigation and remediation efforts.
*   **Data Breach:** Sensitive data within the deleted emails might be exposed or exfiltrated, leading to regulatory fines and reputational damage.
*   **Business Disruption:** The compromised account can be used to send malicious emails, disrupt business operations, and damage relationships with clients and partners.
*   **Compliance Violations:** Deletion of emails may violate compliance regulations regarding data retention and record keeping.

## Recommendation

*   Deploy the provided Sigma rule `O365 Excessive Email Hard Deletes` to your SIEM and tune the threshold (`count > 50 OR file_size > 10`) to match your organization's baseline email activity.
*   Investigate any alerts triggered by the `O365 Excessive Email Hard Deletes` Sigma rule to determine if the hard deletes are legitimate or indicative of a compromised account.
*   Implement multi-factor authentication (MFA) for all O365 accounts to reduce the risk of account compromise.
*   Review and enforce O365 audit logging policies to ensure that all relevant activity is being logged and retained.
*   Educate users about phishing and other social engineering techniques to prevent account compromise.
*   Implement the `O365 Email Hard Delete from Unusual Location` Sigma rule to detect hard deletes originating from unusual IP addresses.
*   Use drilldown searches to Investigate Email for suspicious users.
