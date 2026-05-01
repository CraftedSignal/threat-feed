---
title: Microsoft IIS Connection String Decryption via aspnet_regiis
slug: 2024-01-iis-connection-string-decryption
description: An attacker with Microsoft IIS web server access can decrypt and dump hardcoded connection strings, such as MSSQL service account passwords, using the aspnet_regiis utility, potentially leading to credential compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - iis
  - aspnet_regiis
  - windows
vendors:
  - Microsoft
products:
  - IIS
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.netspi.com/blog/technical-blog/network-pentesting/decrypting-iis-passwords-to-break-out-of-the-dmz-part-1/
  - https://symantec-enterprise-blogs.security.com/blog-post/greenbug-espionage-telco-south-asia
rules:
  - title: Detect IIS Connection String Decryption
    description: Detects the usage of aspnet_regiis.exe to decrypt IIS connection strings, potentially indicating credential access attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
  - title: Detect Renamed aspnet_regiis Connection String Decryption
    description: Detects the usage of a renamed aspnet_regiis.exe to decrypt IIS connection strings.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
  - title: Detect aspnet_regiis connectionStrings Decryption via command line
    description: Detects aspnet_regiis with connectionStrings decryption parameters in command line arguments.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This threat involves the decryption of Microsoft IIS connection strings using the `aspnet_regiis` utility. An attacker who has gained unauthorized access to an IIS web server, typically through a webshell or similar exploit, can leverage this technique to extract sensitive information. The `aspnet_regiis` tool, a legitimate .NET utility, is misused to decrypt connection strings, which often contain hardcoded credentials for databases like MSSQL. This allows the attacker to potentially compromise service accounts and gain further access to the compromised network. The described behavior has been observed in relation to espionage campaigns targeting telecommunications in South Asia, as detailed by Symantec. Defenders should be aware that successful exploitation allows for lateral movement and data exfiltration.

## Attack Chain

1. The attacker gains initial access to a Microsoft IIS web server, often through exploiting a vulnerability that enables webshell deployment.
2. The attacker uses the webshell to execute commands on the compromised server.
3. The attacker uses `aspnet_regiis.exe` with the `-pdf` or `-pd` options to decrypt the `connectionStrings` section of the web.config file.
4. The command `aspnet_regiis.exe -pdf connectionStrings <application_path>` is used to decrypt the connection strings for a specific application.
5. The attacker retrieves the decrypted connection strings, which may contain usernames, passwords, and connection details for MSSQL or other databases.
6. The attacker uses the compromised credentials to access the database server and potentially other systems on the network, achieving lateral movement.
7. The attacker may then exfiltrate sensitive data from the database server.
8. The attacker uses gathered credentials to perform further actions or maintain persistence.

## Impact

Successful exploitation can lead to the exposure of sensitive database credentials, allowing attackers to access and exfiltrate confidential information. This can result in significant data breaches, financial losses, and reputational damage. Depending on the compromised accounts' privileges, attackers could gain control over critical systems and services. Compromised credentials may allow lateral movement to other systems and applications within the network.

## Recommendation

*   Deploy the Sigma rule "Detect IIS Connection String Decryption" to your SIEM and tune for your environment to detect the usage of `aspnet_regiis.exe` with connection string decryption parameters.
*   Monitor process creation events for `aspnet_regiis.exe` with arguments containing `connectionStrings`, `-pdf`, or `-pd` (per the detection rule) to identify potential exploitation attempts.
*   Implement strict access controls on IIS web servers to limit the ability of attackers to execute arbitrary commands.
*   Review IIS web server configurations for weak or hardcoded credentials in connection strings and implement secure credential management practices.
*   Enable Sysmon process creation logging to capture command line arguments for executed processes and facilitate detection of malicious activity.
