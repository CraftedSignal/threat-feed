---
title: IIS AppCmd Tool Used to Dump Service Account Credentials
slug: 2024-01-iis-appcmd-credential-dump
description: Attackers with access to IIS web servers may use the AppCmd command-line tool to dump sensitive configuration data, including application pool credentials, potentially leading to lateral movement and privilege escalation.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - iis
  - appcmd
  - windows
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
  - https://attack.mitre.org/techniques/T1003/
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1552/001/
rules:
  - title: Detect IIS AppCmd Usage to Dump Credentials
    description: Detects the use of AppCmd to list IIS configuration with parameters indicative of credential dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
      - T1552
      - T1552.001
    data_sources:
      - process_creation
      - windows
  - title: Detect IIS AppCmd Usage to Dump Full Configuration
    description: Detects the use of AppCmd to list the full IIS configuration, which may expose credentials.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1003
      - T1552
      - T1552.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers who have gained a foothold on a Windows web server running Internet Information Services (IIS) may attempt to extract sensitive information, such as application pool credentials, to facilitate lateral movement and privilege escalation. This is achieved by leveraging the AppCmd.exe utility, a command-line tool used to manage IIS configurations. By issuing specific commands, attackers can dump the entire web server configuration or target specific fields containing credential-related data, exposing usernames, passwords, and connection strings in clear text. Successful exploitation allows attackers to reuse these credentials to access other systems within the environment, potentially leading to significant data breaches or system compromise. This technique is particularly effective against organizations that store sensitive credentials within their IIS configurations.

## Attack Chain

1.  The attacker gains initial access to the Windows web server, often through a web shell or by exploiting a vulnerability in a web application.
2.  The attacker executes `appcmd.exe` via the command line.
3.  The attacker uses the `list` argument to enumerate application pools or other relevant IIS configurations.
4.  The attacker uses `/text:*password*`, `/text:*processModel*`, `/text:*userName*`, `/config` or `*connectionstring*` parameters with `appcmd.exe` to filter the output and specifically target credential-related data. Alternatively the attacker may use `/text:*` to output the full configuration.
5.  `appcmd.exe` outputs the requested configuration data, which may include usernames, passwords, and connection strings in clear text.
6.  The attacker parses the output to extract valid credentials.
7.  The attacker uses the extracted credentials to authenticate to other systems or services within the network.
8.  The attacker achieves lateral movement, privilege escalation, and access to sensitive data.

## Impact

Successful exploitation allows attackers to recover service account passwords and other sensitive credentials stored within the IIS configuration. This can lead to unauthorized access to databases, file shares, and other internal systems, potentially resulting in data breaches, financial loss, and reputational damage. While the rule itself is low severity, the subsequent impact of exposed credentials can be severe.

## Recommendation

*   Deploy the "Microsoft IIS Service Account Password Dumped" Sigma rule to your SIEM to detect the use of `appcmd.exe` to dump sensitive IIS configuration data.
*   Review IIS and web server activity for signs of exploitation, such as requests to newly created ASPX or PHP files as suggested in the rule's Triage and Analysis section.
*   Enable Sysmon process creation logging to activate the rules above and provide detailed process execution data.
*   Implement the password rotation for affected service accounts as suggested in the rule's Triage and Analysis section.
