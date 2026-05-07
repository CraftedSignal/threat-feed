---
title: PAN-OS Authentication Portal Remote Code Execution Vulnerability
slug: 2026-05-panos-rce
description: An unauthenticated remote code execution vulnerability exists in the PAN-OS Authentication Portal (Captive Portal) service, potentially allowing attackers to execute arbitrary code with root privileges on PA-Series and VM-Series firewalls by sending crafted network packets.
date: "2026-05-07T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - network
vendors:
  - Palo Alto Networks
products:
  - PAN-OS
  - PA-Series firewalls
  - VM-Series firewalls
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://www.cisecurity.org/advisory/a-vulnerability-in-pan-os-could-allow-for-remote-code-execution_2026-043
rules:
  - title: Detect PAN-OS Authentication Portal Exploitation Attempt
    description: Detects network traffic potentially exploiting the PAN-OS Authentication Portal vulnerability by looking for abnormal packet structures. This rule detects abnormal packets being sent to the PAN-OS Authentication Portal.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - network_connection
      - palo_alto_networks
  - title: Detect PAN-OS Root Shell Activity
    description: Detects potential post-exploitation activity on a PAN-OS firewall by monitoring for root shell commands. After successful exploitation the attacker may use a shell.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability resides within the Authentication Portal, also known as Captive Portal, service of PAN-OS, the operating system for Palo Alto Networks next-generation firewalls. This flaw enables an unauthenticated remote attacker to execute arbitrary code with root privileges on affected firewalls. The vulnerability impacts PA-Series and VM-Series firewalls. Successful exploitation bypasses authentication and grants the attacker complete control over the firewall, potentially leading to network compromise, data exfiltration, or denial of service. Defenders must promptly apply the appropriate patches or mitigations to prevent exploitation.

## Attack Chain

1.  The attacker identifies a vulnerable PAN-OS firewall with the Authentication Portal service enabled.
2.  The attacker crafts a malicious network packet specifically designed to exploit the vulnerability in the Authentication Portal service.
3.  The attacker sends the specially crafted packet to the targeted firewall on the port used by the Authentication Portal service (typically TCP port 443).
4.  The vulnerable code within the Authentication Portal service fails to properly handle the malicious packet.
5.  This leads to a buffer overflow or other memory corruption error.
6.  The attacker leverages this memory corruption to inject and execute arbitrary code.
7.  The injected code executes with root privileges due to the elevated permissions of the Authentication Portal service.
8.  The attacker gains complete control over the firewall and can perform actions such as modifying firewall rules, accessing sensitive data, or pivoting to other internal networks.

## Impact

Successful exploitation of this vulnerability grants an unauthenticated attacker complete control over the affected Palo Alto Networks firewalls. This can lead to a complete compromise of the network perimeter, allowing attackers to bypass security controls, exfiltrate sensitive data, or launch further attacks against internal systems. The root-level access obtained enables attackers to disable security features, modify configurations, and potentially use the compromised firewall as a persistent backdoor.

## Recommendation

*   Apply the security patches released by Palo Alto Networks immediately to all affected PA-Series and VM-Series firewalls running PAN-OS to remediate the vulnerability.
*   Monitor network traffic for suspicious packets targeting the Authentication Portal service on PAN-OS firewalls, using a network intrusion detection system (NIDS).
*   Deploy the Sigma rule "Detect PAN-OS Authentication Portal Exploitation Attempt" to detect malicious packets attempting to exploit the vulnerability.
