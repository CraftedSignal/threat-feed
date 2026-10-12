---
title: Credential Dumping via Esentutl.exe
slug: 2026-10-esentutl-sam-copy
description: Attackers utilize the legitimate Windows utility esentutl.exe to perform unauthorized copies of the SAM and ntds.dit files for offline credential extraction, facilitating privilege escalation and lateral movement.
date: "2026-10-12T17:43:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*
tags:
  - credential-dumping
  - living-off-the-land
  - windows
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.002
    technique_name: 'OS Credential Dumping: Security Account Manager'
    evidence: The following analytic detects the use of esentutl.exe to access credentials stored in the ntds.dit or SAM file.
    confidence_band: high
references:
  - https://attack.mitre.org/software/S0404/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md
rules:
  - title: Detect Esentutl SAM or NTDS Copy
    description: Detects the execution of esentutl.exe with command-line arguments targeting the SAM or NTDS database files, commonly used for credential dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor for esentutl.exe usage
      owner: Detection Engineering
      due: 48h
      evidence: Source supports this as a primary detection method
  mitigation_plan:
    - priority: medium_term
      action: Enable Credential Guard on all endpoints
      owner: IT Operations
      addresses: Credential dumping techniques
      evidence: Industry standard mitigation for credential theft
---

The `esentutl.exe` utility is a legitimate Windows binary designed for database maintenance, specifically for the Extensible Storage Engine (ESE). Threat actors frequently abuse this binary to bypass security controls by performing unauthorized copies of sensitive credential databases, including the Security Account Manager (SAM) hive and the Active Directory database (ntds.dit). By creating an offline copy of these files, attackers can perform offline password cracking or extract secrets, significantly increasing the risk of lateral movement and full domain compromise. This technique is categorized as "Living off the Land" (LotL), as it relies on signed, native system tools that are often overlooked by standard signature-based antivirus solutions. Defenders should focus on process execution patterns where `esentutl.exe` interacts with these high-value files to identify potential credential dumping activity.

## Attack Chain

1. Attacker gains initial access to a Windows system via phishing or exploitation.
2. Attacker performs local enumeration to identify system paths for sensitive files.
3. Attacker executes `esentutl.exe` via command line with administrative privileges.
4. The utility is invoked with parameters targeting `%SystemRoot%\System32\config\SAM` or `ntds.dit`.
5. `esentutl.exe` creates a volume shadow copy or a direct database copy of the targeted file.
6. The copied file is staged in a temporary directory such as `C:\Windows\Temp` or `\Users\Public`.
7. Attacker exfiltrates the staged file to a remote server for offline analysis.
8. Attacker uses tools like Mimikatz or Impacket to extract credentials from the dumped files to escalate privileges.

## Impact

Successful execution of this technique leads to the acquisition of NTLM hashes or plaintext credentials for local or domain-level accounts. This outcome enables attackers to move laterally across the network, escalate privileges, and maintain long-term persistent access. If compromised credentials include domain administrative accounts, the entire Active Directory forest is at risk of full control and data exfiltration.

## Recommendation

Prioritize the identification of `esentutl.exe` command-line patterns that reference sensitive database files.

* Deploy the provided Sigma rule to detect process execution of `esentutl.exe` targeting SAM or ntds.dit.
* Configure EDR telemetry to capture full command-line arguments for all executions of `esentutl.exe`.
* Monitor for abnormal file creation events in common staging locations (e.g., `C:\Windows\Temp`, `C:\Users\Public`).
* Restrict administrative access to systems and implement "Credential Guard" on domain-joined endpoints to mitigate the utility of extracted hashes.
