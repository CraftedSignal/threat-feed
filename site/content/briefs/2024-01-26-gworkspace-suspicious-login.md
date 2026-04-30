---
title: Google Workspace Suspicious Login Activity
slug: 2024-01-26-gworkspace-suspicious-login
description: Detect Google Workspace login activity that Google has classified as suspicious, potentially indicating initial access, privilege escalation, defense evasion, or persistence attempts.
date: "2024-01-26T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - privilege-escalation
  - defense-evasion
  - persistence
  - gworkspace
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging
  - https://cloud.google.com/logging/docs/audit/understanding-audit-logs
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login#suspicious_login
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login#suspicious_login_less_secure_app
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login#suspicious_programmatic_login
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/login/gcp_gworkspace_suspicious_login.yml
rules:
  - title: Gworkspace Suspicious Login Less Secure App
    description: Detects Google Workspace login activity classified as suspicious due to the use of less secure app.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1078.004
    data_sources:
      - gcp
      - google_workspace.login
  - title: Gworkspace Suspicious Programmatic Login
    description: Detects Google Workspace login activity classified as suspicious programmatic login.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1078.004
    data_sources:
      - gcp
      - google_workspace.login
  - title: Gworkspace Suspicious Login
    description: Detects Google Workspace login activity classified as suspicious login.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1078.004
    data_sources:
      - gcp
      - google_workspace.login
rules_count: 3
---

This brief focuses on detecting suspicious login activity within Google Workspace environments, as flagged by Google's internal risk assessment mechanisms. Google Workspace logs login events and classifies them based on various risk factors, including the use of less secure applications, programmatic logins, and other anomalies. This detection capability is crucial for identifying potential compromises, unauthorized access attempts, and malicious activities within the Google Workspace ecosystem. Analyzing these flagged events allows security teams to proactively respond to threats before they escalate, preventing data breaches and maintaining the integrity of sensitive information. This alert focuses on logins classified as 'suspicious_login_less_secure_app', 'suspicious_login', and 'suspicious_programmatic_login'.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access using compromised credentials or brute-force techniques targeting Google Workspace accounts.
2.  **Login Attempt:** The attacker attempts to log in to a Google Workspace account using a less secure application (e.g., an older email client without modern authentication) or via programmatic login.
3.  **Suspicious Activity Detection:** Google's internal systems analyze the login attempt and flag it as suspicious based on various risk factors, such as unusual location, time of day, or login method.
4.  **Event Logging:** Google Workspace logs the suspicious login event, including the reason for the classification (e.g., 'suspicious_login_less_secure_app').
5.  **Potential Privilege Escalation:** Upon successful login, the attacker may attempt to escalate privileges within the Google Workspace environment to gain broader access.
6.  **Defense Evasion:** The attacker might use techniques to evade detection, such as disabling security features or modifying audit logs.
7.  **Persistence:** The attacker establishes persistence by creating new accounts, modifying existing ones, or installing malicious apps.
8.  **Data Exfiltration/Malicious Activity:** The attacker uses the compromised account to exfiltrate sensitive data or perform other malicious activities, such as sending phishing emails.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data stored within Google Workspace, including emails, documents, and other files. This can result in data breaches, financial loss, and reputational damage. The number of affected users depends on the scope of the compromised account and the attacker's ability to escalate privileges. Targeted sectors are broad, affecting any organization relying on Google Workspace for collaboration and data storage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious login activity classified by Google Workspace (logsource: `gcp`, service: `google_workspace.login`).
*   Investigate any alerts generated by the Sigma rule to determine the legitimacy of the login attempt and take appropriate action, such as resetting passwords or disabling compromised accounts.
*   Enforce multi-factor authentication (MFA) for all Google Workspace accounts to mitigate the risk of credential compromise.
*   Disable or restrict the use of less secure apps within Google Workspace to reduce the attack surface.
*   Monitor Google Workspace audit logs for other suspicious activities, such as unusual file access or data exfiltration attempts.
