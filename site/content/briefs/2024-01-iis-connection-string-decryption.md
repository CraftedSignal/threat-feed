---
title: Microsoft IIS Connection Strings Decryption via aspnet_regiis
slug: 2024-01-iis-connection-string-decryption
description: An attacker with Microsoft IIS web server access can decrypt and dump hardcoded connection strings, such as the MSSQL service account password, using the aspnet_regiis command.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - iis
vendors:
  - Microsoft
products:
  - IIS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://blog.netspi.com/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/greenbug-espionage-telco-south-asia
rules:
  - title: IIS Connection Strings Decryption via aspnet_regiis
    description: Detects the use of aspnet_regiis to decrypt IIS connection strings, potentially revealing sensitive credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
      - T1552.001
    data_sources:
      - process_creation
      - windows
  - title: IIS aspnet_regiis Renamed Executable
    description: Detects the use of aspnet_regiis under a different name to evade defenses.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
      - T1036
      - T1552.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat involves the exploitation of Microsoft IIS web servers to decrypt sensitive connection strings. An attacker, potentially gaining access via a webshell or similar means, can leverage the `aspnet_regiis` tool to decrypt and extract hardcoded connection strings, including those containing MSSQL service account passwords. This can lead to a significant compromise of the affected system and connected resources. The attack leverages a legitimate tool in an unintended way to expose sensitive information. This activity is commonly observed after initial compromise and can lead to lateral movement and data exfiltration. Defenders should monitor for the execution of `aspnet_regiis` with specific arguments related to connection string decryption.

## Attack Chain

1.  The attacker gains initial access to the IIS server, possibly through a webshell upload vulnerability or compromised credentials.
2.  The attacker uses the webshell to execute commands on the IIS server.
3.  The attacker executes `aspnet_regiis.exe` with the `connectionStrings` and `-pdf` arguments.
4.  `aspnet_regiis.exe` decrypts the connection strings stored in the IIS configuration files.
5.  The attacker retrieves the decrypted connection strings, which may contain sensitive credentials such as database passwords.
6.  The attacker uses the stolen credentials to access the MSSQL database server.
7.  The attacker performs unauthorized actions on the database, such as data exfiltration or privilege escalation.
8.  The attacker uses the compromised database server as a pivot point for further lateral movement within the network.

## Impact

Successful exploitation allows attackers to steal sensitive credentials, such as database passwords. This can lead to unauthorized access to databases, data exfiltration, and further compromise of the network. The impact could include data breaches, financial loss, and reputational damage. Organizations in various sectors that rely on Microsoft IIS web servers are potentially at risk. The severity depends on the sensitivity of the data stored in the databases accessed with the stolen credentials.

## Recommendation

*   Deploy the Sigma rule "IIS Connection Strings Decryption via aspnet_regiis" to detect the execution of `aspnet_regiis.exe` with the `connectionStrings` and `-pdf` arguments (see "rules" section).
*   Monitor process creation events for `aspnet_regiis.exe` with arguments related to connection string decryption. Enable Sysmon process creation logging to enhance visibility.
*   Review IIS server logs for suspicious activity, especially related to webshell access.
*   Implement the remediation steps in the "note" field to contain an incident.
*   Ensure that all IIS servers are patched against known vulnerabilities to prevent initial access.
