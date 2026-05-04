---
title: Potential Active Directory Replication Account Backdoor
slug: 2026-05-dcsync-backdoor
description: Attackers can modify Active Directory object security descriptors to grant DCSync rights to unauthorized accounts, creating a backdoor to extract credential data.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - persistence
  - active-directory
  - dcsync
vendors:
  - Microsoft
products:
  - Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://twitter.com/menasec1/status/1111556090137903104
  - https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf
  - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml
  - https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all
  - https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes
  - https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-in-filtered-set
rules:
  - title: Detect DCSync Rights Modification via nTSecurityDescriptor
    description: Detects modifications to nTSecurityDescriptor attribute granting DCSync rights to a user/computer account.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1003.006
      - T1098
    data_sources:
      - registry_set
      - windows
  - title: Detect Windows Event ID 5136 with DCSync Rights Modification
    description: Detects Windows Event ID 5136 for modification of nTSecurityDescriptor attribute granting DCSync rights.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1003.006
      - T1098
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies modifications to the `nTSecurityDescriptor` attribute within Active Directory (AD) objects that grant DCSync-related permissions to a user or computer account. This technique allows attackers to create a persistent backdoor, enabling them to re-obtain access to user and computer account hashes. The modification involves assigning specific GUIDs that represent replication rights (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`, `89e95b76-444d-4c62-991a-0facbeda640c`) to an account's security descriptor. This allows the attacker to then use DCSync to retrieve credentials from the domain, effectively bypassing normal authentication mechanisms.

## Attack Chain

1. The attacker gains initial access to an account with sufficient privileges to modify Active Directory objects (e.g., Domain Admin).
2. The attacker uses AD management tools (PowerShell, ADSI Edit, etc.) to target a specific user or computer account.
3. The attacker modifies the `nTSecurityDescriptor` attribute of the targeted account.
4. The attacker grants replication rights to the targeted account by adding specific Access Control Entries (ACEs) containing the GUIDs `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`, and `89e95b76-444d-4c62-991a-0facbeda640c`.
5. The attacker uses the DCSync technique, impersonating a domain controller, to request password hashes.
6. The Active Directory server, believing the request is legitimate due to the granted replication rights, provides the attacker with the requested credential information.
7. The attacker obtains password hashes for domain users and computers.
8. The attacker uses the obtained credentials for lateral movement, privilege escalation, or data exfiltration.

## Impact

Successful exploitation allows attackers to compromise the entire Active Directory domain by gaining access to sensitive credential data. This could lead to complete control over the network, including access to critical systems, sensitive data, and the ability to disrupt business operations. The modification of security descriptors creates a persistent backdoor that can be used repeatedly to harvest credentials.

## Recommendation

*   Enable Audit Directory Service Changes to generate the necessary event logs for detection (https://ela.st/audit-directory-service-changes).
*   Deploy the Sigma rule provided below to detect unauthorized modifications to the `nTSecurityDescriptor` attribute. Tune the rule to exclude legitimate administrative accounts or scripts that may perform authorized modifications.
*   Monitor Windows Security Event Logs (event code 5136) for changes to the `nTSecurityDescriptor` attribute and investigate any unexpected modifications, focusing on the presence of DCSync-related GUIDs.
*   Regularly review and audit Active Directory permissions, focusing on accounts with replication rights, to ensure they are legitimate and necessary.
