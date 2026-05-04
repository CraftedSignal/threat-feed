---
title: Suspicious DNS-Named Record Creation in Active Directory Integrated DNS
slug: 2024-05-adidns-record-creation
description: Detection of DNS record creation by non-system accounts within Active Directory Integrated DNS (ADIDNS), which attackers can abuse to perform Dynamic Spoofing attacks, potentially targeting services like WPAD for credential access.
date: "2024-05-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - credential-access
  - windows
  - active-directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
references:
  - https://www.netspi.com/blog/technical/network-penetration-testing/adidns-revisited/
  - https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/wpad-spoofing
rules:
  - title: Creation of a DNS-Named Record
    description: Detects the creation of a dnsNode object in Active Directory by non-system accounts, which is indicative of potential ADIDNS spoofing attacks.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1557.001
    data_sources:
      - process_creation
      - windows
  - title: ADIDNS dnsNode Creation Event
    description: Detects Windows Security Event ID 5137 events indicating a dnsNode object (DNS record) was created in Active Directory, excluding modifications by system accounts.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1557.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Active Directory Integrated DNS (ADIDNS) is a core component of AD DS, storing DNS zones as AD objects. The default permission settings allow any authenticated user to create DNS-named records. This creates an opportunity for attackers to perform Dynamic Spoofing attacks by monitoring LLMNR/NBT-NS requests and creating DNS-named records to target systems or specific services like WPAD. This attack can enable credential access by redirecting traffic through attacker-controlled systems, leading to the capture of sensitive information. This activity is detectable by monitoring Windows event code 5137 related to DNS record creation and filtering out legitimate system accounts.

## Attack Chain

1.  The attacker gains initial access to a domain-joined system, possibly through compromised credentials or phishing.
2.  The attacker passively monitors LLMNR/NBT-NS broadcast traffic to identify systems being requested on the network.
3.  Upon observing a request for a target system (e.g., WPAD), the attacker creates a DNS-named record in ADIDNS that resolves the target system's name to an attacker-controlled IP address. This leverages the default permissions in ADIDNS that allow authenticated users to create DNS records.
4.  When a legitimate user attempts to access the target system, the DNS query resolves to the attacker's IP address.
5.  The user's traffic is redirected to the attacker's system.
6.  The attacker intercepts the user's credentials or other sensitive information.
7.  The attacker may relay captured credentials to other systems on the network.
8.  The attacker achieves credential access and lateral movement within the network.

## Impact

Successful exploitation allows attackers to intercept network traffic, steal credentials, and potentially gain unauthorized access to sensitive systems and data within the Active Directory domain. While the severity is low, it can be a stepping stone to further, more damaging attacks.

## Recommendation

*   Enable "Audit Directory Service Changes" to generate the necessary Windows Security Event Logs (event code 5137) for detection.
*   Deploy the Sigma rule `Creation of a DNS-Named Record` to detect suspicious DNS record creation events.
*   Implement stricter access controls on DNS record creation within Active Directory to limit permissions to only necessary and trusted accounts.
