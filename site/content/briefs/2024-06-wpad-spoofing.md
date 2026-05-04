---
title: Potential WPAD Spoofing via DNS Record Creation
slug: 2024-06-wpad-spoofing
description: Detection of a Windows DNS record creation event (5137) with an ObjectDN attribute containing 'DC=wpad', which indicates a potential WPAD spoofing attack to enable privilege escalation and lateral movement.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - wpad-spoofing
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
references:
  - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/wpad-spoofing#through-adidns-spoofing
  - https://cube0x0.github.io/Pocing-Beyond-DA/
rules:
  - title: Potential WPAD Spoofing via DNS Record Creation
    description: Detects the creation of a DNS record that is potentially meant to enable WPAD spoofing by monitoring Windows Event ID 5137 for specific ObjectDN values.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1557
    data_sources:
      - process_creation
      - windows
  - title: WPAD DNS Record Creation via PowerShell
    description: Detects the creation of a DNS record that is potentially meant to enable WPAD spoofing by monitoring PowerShell command lines.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1557
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Web Proxy Auto-Discovery (WPAD) is a protocol that allows devices to automatically discover proxy settings, but it can be exploited by attackers to redirect traffic through malicious proxies. This detection identifies the creation of a "wpad" DNS record, which is a common technique used in WPAD spoofing attacks. Attackers can disable the Global Query Block List (GQBL) and create a rogue "wpad" record. The event code 5137 is logged when directory service changes are made, and this rule focuses on changes related to the creation of wpad records. This is important for defenders because successful WPAD spoofing can lead to credential access and lateral movement within the network.

## Attack Chain

1. The attacker gains initial access to a system with sufficient privileges to modify DNS records, often an Active Directory account.
2. The attacker disables the Global Query Block List (GQBL) to allow the creation of unauthorized DNS records.
3. The attacker creates a new DNS record for "wpad" in Active Directory DNS, using event code 5137.
4. The 'ObjectDN' attribute of the DNS record contains "DC=wpad,*".
5. Clients on the network query the DNS server for the "wpad" record.
6. The DNS server responds with the attacker-controlled IP address.
7. Clients automatically configure their proxy settings to use the attacker's proxy server.
8. The attacker intercepts network traffic, potentially capturing credentials and sensitive data.

## Impact

Successful WPAD spoofing can allow attackers to intercept sensitive information, including credentials, as users browse the web. This can lead to further compromise of systems and data within the network. While the number of victims is difficult to quantify, the impact can be significant within an organization if the attack is successful. This attack targets organizations using default WPAD settings.

## Recommendation

*   Enable Audit Directory Service Changes to generate Windows Security Event Logs (event code 5137) as described in the setup instructions to ensure the rule functions correctly.
*   Deploy the Sigma rule "Potential WPAD Spoofing via DNS Record Creation" to your SIEM to detect suspicious "wpad" record creations.
*   Review Active Directory change history when the Sigma rule triggers to determine who made the changes to the DNS records and whether these changes were authorized, as outlined in the investigation guide.
*   Regularly verify the configuration of the Global Query Block List (GQBL) to ensure it has not been disabled or altered, as described in the investigation guide.
