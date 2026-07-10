---
title: Exchange Mailbox Export via PowerShell
slug: 2024-10-exchange-mailbox-export
description: Adversaries may use the `New-MailboxExportRequest` PowerShell cmdlet to export mailboxes to PST files for sensitive data collection.
date: "2024-10-26T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - email-collection
  - powershell
  - exchange
vendors:
  - Microsoft
products:
  - Exchange
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
references:
  - https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/
  - https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps
  - https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry
rules:
  - title: Detect Exchange Mailbox Export via PowerShell CommandLine
    description: Detects the use of the New-MailboxExportRequest cmdlet in PowerShell to export mailboxes.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - execution
    techniques:
      - T1059.001
      - T1114
    data_sources:
      - process_creation
      - windows
  - title: Detect Exchange Mailbox Export via PowerShell Process Name
    description: Detects the use of the New-MailboxExportRequest cmdlet by checking the process name and commandline
    platform: sigma
    severity: medium
    tactics:
      - collection
      - execution
    techniques:
      - T1059.001
      - T1114
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can target user email to collect sensitive information from mailboxes, including login credentials, intellectual property, financial data, and personal information. The `New-MailBoxExportRequest` cmdlet allows exporting mailboxes to .pst files. This cmdlet is available in on-premises Exchange. Attackers may assign the "Mailbox Import Export" privilege to accounts to perform exports and collect contents in preparation for exfiltration. This allows attackers to bypass traditional security measures focused on network traffic by collecting data directly on the Exchange server. Defenders should monitor PowerShell command lines for `MailboxExportRequest` and related parameters, especially in environments with on-premises Exchange deployments.

## Attack Chain

1. An attacker gains access to a Windows host within the target environment.
2. The attacker compromises an account with Exchange Management Shell access or sufficient privileges to assign the "Mailbox Import Export" privilege.
3. The attacker uses PowerShell to assign the "Mailbox Import Export" privilege to a compromised account if it doesn't already have the necessary permissions.
4. The attacker uses the `New-MailboxExportRequest` cmdlet in PowerShell to initiate the export of a target mailbox to a .pst file. The command specifies the mailbox to export and the file path for the resulting .pst file.
5. The Exchange server processes the export request, extracting the contents of the mailbox and writing them to the specified .pst file.
6. The attacker accesses the .pst file on the Exchange server.
7. The attacker may compress or archive the .pst file using tools like `7zip.exe` or `rar.exe` to reduce its size for exfiltration.
8. The attacker exfiltrates the .pst file to an external location using tools like `scp.exe`, `pscp.exe`, or `ftp.exe`.

## Impact

Successful execution of this attack can lead to the unauthorized disclosure of sensitive information contained within the exported mailboxes. This can include confidential business documents, financial records, personally identifiable information (PII), and other proprietary data. A successful attack exposes the organization to data breaches, compliance violations, reputational damage, and potential financial losses. The number of affected mailboxes and the sensitivity of the data contained within them will determine the overall impact.

## Recommendation

*   Monitor process creation events for PowerShell processes (`powershell.exe`, `pwsh.exe`, `powershell_ise.exe`) executing with command lines containing `MailboxExportRequest` or `*-Mailbox*-ContentFilter*` using the Sigma rule provided below.
*   Investigate and audit the assignment of the "Mailbox Import Export" privilege within the Exchange environment to identify any unauthorized or suspicious activity.
*   Enable Sysmon process creation logging to capture detailed command line arguments for PowerShell processes.
*   Review the references provided to understand the context and potential indicators related to this activity.
