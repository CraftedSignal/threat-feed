---
title: Active Directory msPKIAccountCredentials Modification
slug: 2024-01-cred-roaming
description: Attackers can modify the msPKIAccountCredentials attribute in Active Directory user objects to abuse credential roaming, potentially overwriting files for privilege escalation, by injecting malicious credential objects.
date: "2024-01-26T18:25:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - credential-roaming
  - active-directory
  - windows
vendors:
  - Microsoft
products:
  - Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.mandiant.com/resources/blog/apt29-windows-credential-roaming
  - https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136
rules:
  - title: Modification of msPKIAccountCredentials in Active Directory
    description: Detects modifications to the msPKIAccountCredentials attribute in Active Directory, excluding the SYSTEM account.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1098
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Accessing Active Directory Objects
    description: Detects unusual processes accessing Active Directory objects, which could indicate malicious modification attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1018
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The msPKIAccountCredentials attribute in Active Directory stores encrypted credential data, including private keys and certificates. An attacker can modify this attribute to escalate privileges by overwriting an arbitrary file. This is achieved by modifying the msPKIAccountCredentials attribute of a user object with malicious credential objects. Successful exploitation allows the attacker to gain elevated privileges within the domain. The attack leverages the Windows credential roaming feature to inject these malicious credentials. This activity is detected via event code 5136 in the Windows Security Event Logs.

## Attack Chain

1. An attacker gains initial access to a domain-joined system, possibly through compromised credentials or phishing.
2. The attacker identifies a target Active Directory user account to manipulate.
3. The attacker crafts a malicious payload containing an encrypted credential object.
4. The attacker uses a tool or script (e.g., PowerShell, adsiedit.msc) to modify the target user's msPKIAccountCredentials attribute in Active Directory.
5. The attacker triggers credential roaming, causing the modified attribute to be propagated to other domain-joined systems where the target user logs in.
6. When the target user logs in, the malicious credential object is processed, potentially overwriting a critical system file.
7. The attacker leverages the overwritten file to execute arbitrary code with elevated privileges.
8. The attacker achieves privilege escalation and gains further access to the network.

## Impact

Successful modification of the msPKIAccountCredentials attribute can lead to complete domain compromise. Attackers can gain control over critical systems and data within the Active Directory environment. While the exact number of potential victims is unknown, any organization utilizing Active Directory is potentially vulnerable. This attack allows for lateral movement, data exfiltration, and potentially the deployment of ransomware.

## Recommendation

*   Enable "Audit Directory Service Changes" to generate the necessary event logs (https://ela.st/audit-directory-service-changes).
*   Deploy the Sigma rule `Modification of msPKIAccountCredentials in Active Directory` to detect suspicious modifications of the attribute.
*   Review and harden Active Directory access controls, limiting which accounts can modify the `msPKIAccountCredentials` attribute.
*   Monitor event code 5136 in the Windows Security Event Logs for modifications to the `msPKIAccountCredentials` attribute.
*   Create exceptions in your SIEM for authorized administrative accounts that legitimately modify this attribute to reduce false positives as described in the "False positive analysis" section above.
