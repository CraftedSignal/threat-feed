---
title: O365 Add App Role Assignment Grant User
slug: 2024-01-03-o365-app-role-assignment
description: This analytic detects the addition of an application role assignment grant to a user in Office 365, which can indicate unauthorized privilege escalation or the assignment of sensitive roles, leading to unauthorized access within the Office 365 environment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - office365
  - azuread
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Office 365
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136
    technique_name: Create Account
references:
  - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf
  - https://www.cisa.gov/uscert/ncas/alerts/aa21-008a
rules:
  - title: Detect O365 Add App Role Assignment Grant to User
    description: Detects the addition of an application role assignment grant to a user in Office 365, which can indicate unauthorized privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1136.003
    data_sources:
      - webserver
      - o365
  - title: Detect O365 App Role Assignment Modification by Unusual User Agent
    description: Detects modifications of application role assignments in O365 using uncommon or suspicious user agents.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1136.003
    data_sources:
      - webserver
      - o365
rules_count: 2
---

This detection focuses on identifying the addition of application role assignments to users within Microsoft Office 365. The activity is monitored through the `o365_management_activity` dataset, specifically targeting "Add app role assignment grant to user" operations. This is significant because unauthorized modifications to user roles can lead to privilege escalation, allowing attackers to gain elevated access to critical resources and data within the O365 environment. Monitoring this activity is crucial for defenders to identify and prevent potential breaches or internal misuse. References such as FireEye's report on UNC2452 and CISA Alert AA21-008A highlight the importance of monitoring such events, as attackers often leverage compromised credentials and elevated privileges to further their objectives within the cloud environment. The provided detection logic is designed to be implemented within Splunk environments utilizing the Microsoft Office 365 add-on.

## Attack Chain

1. An attacker gains initial access to a compromised user account within the Office 365 environment (T1136.003).
2. The attacker uses the compromised account to authenticate to Azure Active Directory.
3. The attacker attempts to add an application role assignment grant to a user, modifying the user's permissions.
4. This action generates an "Add app role assignment grant to user" event within the `o365_management_activity` logs.
5. The detection identifies this specific event, triggered by the attacker's attempt to elevate privileges.
6. If successful, the attacker escalates their privileges, gaining unauthorized access to sensitive data and resources.
7. The attacker may then use these elevated privileges to move laterally within the O365 environment.
8. The final objective is to exfiltrate sensitive data or establish persistence within the environment.

## Impact

A successful attack could lead to significant data breaches, unauthorized access to sensitive information, and potential reputational damage. By escalating privileges, attackers can bypass security controls and access critical business applications and data stored within the Office 365 environment. The number of affected users and the extent of the damage will depend on the specific roles granted and the sensitivity of the accessed data. This can affect any organization using Office 365, ranging from small businesses to large enterprises, and can have significant financial and operational consequences.

## Recommendation

*   Install and configure the Splunk Microsoft Office 365 add-on to collect the necessary logs (data_source).
*   Deploy the provided Sigma rule to your Splunk environment to detect suspicious "Add app role assignment grant to user" events and tune the rule for your specific environment.
*   Investigate any detected events to determine if the role assignment was authorized and legitimate, referencing the detection results for specific users and destinations as outlined in the drilldown searches.
*   Monitor the `o365_management_activity` logs for unusual patterns of role assignment changes, using the provided search query as a starting point.
*   Review user accounts added to privileged roles.
