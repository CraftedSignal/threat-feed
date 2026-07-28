---
title: Credential Manager Access By Uncommon Applications
slug: 2026-07-credential-manager-access
description: A SigmaHQ detection rule identifies suspicious processes accessing Windows credential manager and vault files, potentially indicating credential theft by tools like Mimikatz, enabling lateral movement and data exfiltration.
date: "2026-07-28T08:32:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-theft
  - mimikatz
  - dpapi
  - windows
  - post-exploitation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Detects suspicious processes based on name and location that access the windows credential manager and vault. Which can be a sign of credential stealing. Example case would be usage of mimikatz 'dpapi::cred' function
    confidence_band: high
references:
  - https://hunter2.gitbook.io/darthsidious/privilege-escalation/mimikatz
  - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_access/file_access_win_susp_credential_manager_access.yml
rules:
  - title: Credential Manager Access By Uncommon Applications
    description: Detects suspicious processes based on name and location that access Windows credential manager and vault files, which can be a sign of credential stealing, such as Mimikatz 'dpapi::cred' function.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_access
      - windows
rules_count: 1
---

This brief details a detection rule from SigmaHQ designed to identify suspicious access to Windows credential manager and vault files, a strong indicator of credential theft attempts. This activity is frequently associated with post-exploitation tools, such as Mimikatz, which can dump cached credentials (e.g., using its "dpapi::cred" function). The detection specifically targets processes that are not part of common system directories (like `C:\Program Files` or `C:\Windows\system32`) or `explorer.exe`, when they attempt to access specific `AppData` and `ProgramData` paths where sensitive credentials and vault data are stored. This type of activity is critical for defenders to monitor, as stolen credentials can facilitate lateral movement, privilege escalation, and further compromise within an organization's environment.

## Impact

Successful credential theft allows attackers to gain unauthorized access to user accounts, services, and sensitive data. This compromise can facilitate lateral movement within the network, escalate attacker privileges, and ultimately lead to data exfiltration, complete system compromise, or the deployment of further malicious payloads such as ransomware. The number of potential victims can range from a single compromised user to an entire organization, depending on the scope of the credential theft and the privileges associated with the stolen credentials. Industries targeted by credential theft are typically broad, as this is a foundational tactic in the vast majority of cyberattacks.

## Recommendation

* Deploy the `Credential Manager Access By Uncommon Applications` Sigma rule to your SIEM to detect suspicious access patterns to credential manager files.
* Ensure the `Microsoft-Windows-Kernel-File ETW provider` is enabled on Windows endpoints to provide the necessary file access logging for this detection rule.
* Review logs for `file_access` events related to `\AppData\Local\Microsoft\Credentials\`, `\AppData\Roaming\Microsoft\Credentials\`, `\AppData\Local\Microsoft\Vault\`, and `\ProgramData\Microsoft\Vault\` originating from processes outside standard system directories.
