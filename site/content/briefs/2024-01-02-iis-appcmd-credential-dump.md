---
title: Microsoft IIS Service Account Password Dump via AppCmd
slug: 2024-01-02-iis-appcmd-credential-dump
description: An attacker with IIS web server access via a web shell can extract service account passwords by requesting full configuration output or targeting credential-related fields using the AppCmd tool.
date: "2024-01-02T12:00:00Z"
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
affected_os:
  - Windows
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
rules:
  - title: Detect IIS AppCmd Credential Dumping
    description: Detects the execution of `appcmd.exe` with arguments indicative of credential dumping from IIS configuration files.
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
  - title: Detect IIS AppCmd Credential Dumping - Original Filename
    description: Detects the execution of renamed `appcmd.exe` with arguments indicative of credential dumping from IIS configuration files by matching on the original filename.
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
rules_count: 2
---

The Microsoft Internet Information Services (IIS) command-line tool, AppCmd, is used to manage IIS configurations. An attacker who gains access to an IIS web server, often through a web shell, can leverage AppCmd to dump sensitive configuration data, including application pool credentials. This involves requesting full configuration output or targeting specific credential-related fields, potentially exposing service account passwords in clear text. This activity is typically post-compromise and indicates an attempt to escalate privileges or move laterally within the network. The risk lies in the exposure of credentials that can be reused to access other systems or data.

## Attack Chain

1. An attacker gains initial access to the IIS web server, commonly through exploiting a vulnerability or uploading a web shell (e.g., ASPX or PHP).
2. The attacker uses the web shell to execute commands on the server.
3. The attacker uses `appcmd.exe` to list the IIS configuration.
4. The `appcmd.exe` command includes arguments to display specific configuration sections related to credentials, such as application pool identities, process model settings, or connection strings. Examples of command line arguments used are `/text:*password*`, `/text:*processModel*`, `/text:*userName*`, `/config`, or `*connectionstring*`.
5. `appcmd.exe` outputs the requested configuration data to the console, which includes sensitive information like usernames and passwords in plaintext.
6. The attacker captures the output containing the credentials.
7. The attacker uses the acquired credentials to move laterally to other systems on the network or access sensitive data.

## Impact

Successful exploitation can lead to the exposure of sensitive credentials, enabling attackers to perform lateral movement, privilege escalation, and data exfiltration. The number of potential victims is dependent on the scope of the attacker's access and the configuration of the IIS server. Sectors commonly targeted include organizations that rely heavily on web applications and services, such as e-commerce, finance, and healthcare. If successful, the attacker can gain complete control over critical systems and data.

## Recommendation

*   Enable Sysmon process creation logging to capture `appcmd.exe` execution with command-line arguments.
*   Deploy the Sigma rule `Detect IIS AppCmd Credential Dumping` to your SIEM and tune for your environment.
*   Monitor IIS and web server activity for signs of exploitation, such as requests to newly created ASPX or PHP files, requests containing command-execution parameters, or uploads to writable web paths.
*   Implement privileged access management (PAM) solutions to restrict the usage of service accounts.
