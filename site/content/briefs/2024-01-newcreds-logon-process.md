---
title: Unusual Process Performing NewCredentials Logon
slug: 2024-01-newcreds-logon-process
description: Anomalous NewCredentials logon events triggered by uncommon processes may indicate access token manipulation for privilege escalation.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - token-manipulation
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://www.elastic.co/pt/blog/how-attackers-abuse-access-token-manipulation
  - https://attack.mitre.org/techniques/T1134/
  - https://attack.mitre.org/techniques/T1134/001/
rules:
  - title: Suspicious NewCredentials Logon by Uncommon Process
    description: Detects NewCredentials logon events performed by processes outside of standard program directories, which may indicate access token manipulation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1134
      - T1134.001
    data_sources:
      - process_creation
      - windows
  - title: NewCredentials Logon with Advapi LogonProcessName
    description: Detects a new credentials logon type with LogonProcessName equal to Advapi, which is often associated with access token manipulation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1134
      - T1134.001
    data_sources:
      - security
      - windows
rules_count: 2
---

The NewCredentials logon type in Windows allows a process to impersonate a user without initiating a new logon session. While legitimate uses exist, adversaries can abuse this mechanism to forge access tokens, enabling privilege escalation and bypassing security controls. This detection focuses on identifying unusual processes that perform NewCredentials logons, excluding common system paths and service accounts. This approach aims to highlight potential access token manipulation attacks that might otherwise go unnoticed. The rule specifically looks for authentication events on Windows systems where the logon type is NewCredentials and the LogonProcessName is Advapi, excluding events where the SubjectUserName ends with '$' (service accounts) and the process executable resides within Program Files or Program Files (x86) directories.

## Attack Chain

1. An attacker gains initial access to a system (e.g., through phishing or exploiting a vulnerability).
2. The attacker deploys or utilizes a tool capable of access token manipulation.
3. The malicious tool generates a NewCredentials logon event using `Advapi*`.
4. The tool attempts to impersonate a privileged user account.
5. The compromised process assumes the identity of the targeted user.
6. The attacker uses the elevated privileges to access sensitive resources or perform unauthorized actions.
7. The attacker attempts to move laterally to other systems within the network, leveraging the stolen credentials.
8. The attacker achieves their final objective, such as data exfiltration or system compromise.

## Impact

Successful exploitation can lead to complete system compromise, data breaches, and lateral movement within the network. The risk score associated with this behavior is 47, indicating a notable level of concern. While the number of victims and targeted sectors is not specified, the potential impact of privilege escalation warrants immediate investigation and remediation.

## Recommendation

*   Deploy the "First Time Seen NewCredentials Logon Process" rule to your SIEM and tune for your environment to detect unusual processes performing NewCredentials logons.
*   Enable Audit Logon to generate the necessary events for the detection rule to function as described in the setup instructions [https://ela.st/audit-logon].
*   Review and update access control policies and token management practices to mitigate the risk of access token manipulation.
*   Consult threat intelligence sources to determine if the identified process or behavior is associated with known malicious activity or threat actors as documented in the reference [https://www.elastic.co/pt/blog/how-attackers-abuse-access-token-manipulation].
