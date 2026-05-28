---
title: Windows AD sIDHistory Attribute Modification Detection
slug: 2026-05-windows-ad-sid-history-addition
description: This analytic detects changes to the sIDHistory attribute of user or computer objects within the same domain using Windows Security Event Codes 4738 and 4742, which can be abused by adversaries to gain unauthorized access, maintain persistence, or escalate privileges by inheriting permissions from another account.
date: "2026-05-28T17:59:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sidhistory
  - active-directory
  - privilege-escalation
  - persistence
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://adsecurity.org/?p=1772
  - https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory?redirectedfrom=MSDN
  - https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-sid-history-attribute
  - https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/sid-history-injection
rules:
  - title: Detect AD sIDHistory Attribute Modification - Same Domain
    description: Detects modifications to the sIDHistory attribute of user or computer objects within the same domain, which can indicate malicious activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1134.005
    data_sources:
      - windows
      - windows
  - title: Detect AD sIDHistory Injection via String Matching
    description: Detects potential sIDHistory injection by matching the target SID to a known SID within the sIDHistory attribute. This is a simplified rule for identifying suspicious patterns and will require tuning.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1134.005
    data_sources:
      - windows
      - windows
rules_count: 2
---

The sIDHistory attribute in Active Directory is a legacy feature that allows users migrating between domains to retain access to resources in their old domain. Attackers can abuse this attribute to grant unauthorized access by injecting SIDs from highly privileged accounts into the sIDHistory of a compromised account. This injection allows the compromised account to inherit the permissions of the privileged account, effectively escalating privileges and potentially achieving domain dominance. This brief focuses on detecting modifications to the sIDHistory attribute within the same domain, which is often indicative of malicious activity, using Windows Security Event Codes 4738 and 4742. The activity allows for persistent access or privilege escalation within the domain, posing a severe security risk.

## Attack Chain

1.  An attacker gains initial access to a user account or computer on the domain. This could be achieved through phishing, credential theft, or exploiting a vulnerability on a domain-joined machine.
2.  The attacker elevates their privileges on the compromised machine, often using local privilege escalation techniques like exploiting misconfigured services or vulnerable drivers.
3.  The attacker uses tools like Mimikatz to obtain credentials for a domain account with sufficient privileges to modify Active Directory attributes.
4.  The attacker modifies the sIDHistory attribute of a target account within the same domain, injecting the SID of a highly privileged account (e.g., Domain Admins). This is done using command-line tools or PowerShell scripts that interact with the Active Directory API.
5.  The attacker authenticates to the domain with the target account. The Kerberos ticket generated for the target account now includes the injected SID in its authorization data.
6.  The attacker accesses resources or performs actions that require the privileges associated with the injected SID. Because the Kerberos ticket contains the SID of the privileged account, the attacker is granted access.
7.  The attacker maintains persistent access by ensuring the injected SID remains in the sIDHistory attribute, even after the initial compromise is remediated.

## Impact

Successful exploitation allows attackers to escalate privileges, gain unauthorized access to sensitive resources, and establish persistent access within the Active Directory domain. This can lead to data breaches, service disruptions, and complete compromise of the domain infrastructure. The scope of impact is potentially domain-wide, affecting all resources and users managed by the compromised Active Directory.

## Recommendation

*   Enable and monitor Windows Security Event Logs for Event Codes 4738 and 4742 to detect modifications to the sIDHistory attribute as described in the overview.
*   Deploy the Sigma rule `Detect AD sIDHistory Attribute Modification - Same Domain` to your SIEM and tune for your environment.
*   Review and restrict the accounts that have permissions to modify the sIDHistory attribute in Active Directory.
*   Investigate any detected sIDHistory modifications within the same domain to determine if they are legitimate or malicious. Use `Windows AD Same Domain SID History Addition` search to investigate potential malicious activity.
*   Regularly audit Active Directory for unauthorized changes to user and computer accounts.
