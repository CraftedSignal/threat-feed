---
title: Detection of Windows Privileged Group Modifications
slug: 2024-11-ad-group-mod
description: This brief covers the detection of modifications to privileged Active Directory groups, potentially linked to the exploitation of CVE-2024-37085, where attackers may attempt to manipulate privileged groups to gain unauthorized access to systems.
date: "2024-11-02T12:00:00Z"
lastmod: "2026-10-12T18:05:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vmware:cloud_foundation:*:*:*:*:*:*:*:*
  - cpe:2.3:o:vmware:esxi:7.0:*:*:*:*:*:*:*
  - cpe:2.3:o:vmware:esxi:8.0:*:*:*:*:*:*:*
tags:
  - active-directory
  - privilege-escalation
  - group-modification
  - windows
  - cve-2024-37085
vendors:
  - VMware
products:
  - ESXi
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136
    technique_name: Create Account
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136
    technique_name: Create Account
cves:
  - id: CVE-2024-37085
    cvss: 6.8
    epss: 0.2677
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-37085
  - https://www.rapid7.com/blog/post/2024/07/30/vmware-esxi-cve-2024-37085-targeted-in-ransomware-campaigns/%5C
  - https://x.com/mthcht/status/1818196168515461431?s=12&t=kwffmj0KM1sZtg3MrqC0QQ
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_esx_admins_group_creation_via_net.yml
rules:
  - title: Detect Addition to Privileged Groups
    description: Detects when a user is added to a privileged group in Windows.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1136.001
    data_sources:
      - security
      - windows
  - title: Detect Removal from Privileged Groups
    description: Detects when a user is removed from a privileged group in Windows.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1136.002
    data_sources:
      - security
      - windows
rules_count: 2
updates:
  - at: "2026-10-12T18:05:08Z"
    level: L2
    summary: added CVE-2024-37085; OS windows server
    sources:
      - splunk-escu
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_esx_admins_group_creation_via_net.yml
---

This brief addresses the threat of unauthorized modifications to privileged groups in Active Directory. The focus is on identifying when actors create, delete, or alter memberships of sensitive groups such as "Domain Admins", "Enterprise Admins", and "ESX Admins". Such actions can be indicative of malicious activity, particularly in the context of exploiting vulnerabilities like CVE-2024-37085, the VMware ESXi Active Directory Integration Authentication Bypass. Successful exploitation could allow attackers to escalate privileges and gain control over critical systems. The detection relies on analyzing Windows Security Event logs, specifically Event Codes 4727, 4731, 4744, 4749, 4754, 4756, 4759, 4783, and 4790. Timely detection of these modifications is crucial for preventing lateral movement and data breaches within the network.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a system within the target network, potentially through exploiting CVE-2024-37085.
2.  Privilege Escalation: The attacker attempts to elevate privileges by exploiting existing vulnerabilities or misconfigurations within the system.
3.  Group Enumeration: The attacker enumerates existing Active Directory groups, specifically targeting privileged groups such as "Domain Admins" and "Enterprise Admins".
4.  Group Modification: The attacker modifies a privileged group, adding a compromised account or creating a new account with elevated privileges. This involves generating Windows Security Event logs 4727, 4731, 4744, 4749, 4754, 4756, 4759, 4783, and 4790.
5.  Credential Access: With elevated privileges, the attacker accesses sensitive credentials and resources within the network.
6.  Lateral Movement: The attacker uses the compromised credentials to move laterally to other systems and resources within the network.
7.  Data Exfiltration/Ransomware Deployment: The attacker exfiltrates sensitive data or deploys ransomware across the compromised systems.

## Impact

Compromising privileged groups within Active Directory can lead to widespread damage across the entire network. Attackers can gain complete control over domain controllers, critical servers, and user accounts. The manipulation of "Domain Admins" or "Enterprise Admins" groups grants attackers unrestricted access to sensitive data, intellectual property, and financial records. In cases involving CVE-2024-37085, the impact is amplified by the potential for widespread ransomware deployment across VMware ESXi environments. The result can be significant financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Enable Windows Security Event logging for Event IDs 4727, 4731, 4744, 4749, 4754, 4756, 4759, 4783, and 4790 to ensure visibility into group modification events.
*   Deploy the provided Sigma rules to your SIEM to detect unauthorized modifications to privileged groups in Active Directory.
*   Investigate and patch CVE-2024-37085 on all VMware ESXi servers to prevent attackers from gaining initial access.
*   Review and harden Active Directory group policies to minimize the risk of unauthorized group modifications.
