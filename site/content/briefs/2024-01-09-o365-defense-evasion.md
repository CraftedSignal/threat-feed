---
title: Defense Evasion via Exchange DLP Policy Removal
slug: 2024-01-09-o365-defense-evasion
description: Attackers may remove or modify Exchange Data Loss Prevention (DLP) policies in Microsoft 365 to evade detection and exfiltrate sensitive data without triggering alerts.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - o365
  - dlp
  - defense_evasion
  - data_exfiltration
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Microsoft Exchange
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/o365/defense_evasion_exchange_dlp_policy_removed.toml
rules:
  - title: Detect DLP Policy Removal via PowerShell
    description: Detects the removal of Data Loss Prevention (DLP) policies in Microsoft 365 Exchange via PowerShell commands.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect DLP Policy Modification via PowerShell
    description: Detects the modification of Data Loss Prevention (DLP) policies in Microsoft 365 Exchange via PowerShell commands.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers with sufficient privileges within a Microsoft 365 environment may target Exchange Data Loss Prevention (DLP) policies to facilitate data exfiltration or other malicious activities. By removing or modifying these policies, attackers can disable controls that would otherwise prevent sensitive information from leaving the organization. This tactic allows adversaries to operate with less risk of detection, potentially leading to significant data breaches. The scope of this attack depends on the extent of the attacker's access and the breadth of the compromised policies.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to a Microsoft 365 account with administrative privileges, potentially through phishing, credential stuffing, or other methods.
2. **Privilege Escalation:** If the initial account lacks sufficient privileges, the attacker attempts to escalate privileges within the Microsoft 365 environment.
3. **Discovery:** The attacker uses PowerShell cmdlets like `Get-DlpPolicy` to identify existing DLP policies within the Exchange environment.
4. **Defense Evasion:** The attacker uses PowerShell cmdlets like `Remove-DlpPolicy` or `Set-DlpPolicy` to remove or modify existing DLP policies. For example, they might disable a policy that prevents the transmission of sensitive financial data.
5. **Data Exfiltration:** With DLP policies disabled or weakened, the attacker exfiltrates sensitive data via email, file sharing, or other allowed channels.
6. **Cover Tracks:** The attacker may attempt to delete audit logs or modify other settings to conceal their activity. This might involve disabling auditing for specific mailboxes or DLP policies.

## Impact

Successful removal or modification of DLP policies can lead to significant data breaches. Sensitive information, such as financial records, customer data, or intellectual property, can be exfiltrated without detection. The number of affected individuals and the financial impact can vary greatly depending on the scope of the attack and the type of data compromised. Organizations in highly regulated sectors, such as finance and healthcare, may face significant fines and reputational damage.
