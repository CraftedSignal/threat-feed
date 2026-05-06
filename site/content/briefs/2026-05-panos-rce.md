---
title: Palo Alto PAN-OS Unauthenticated Root RCE via User-ID Authentication Portal
slug: 2026-05-panos-rce
description: CVE-2026-0300 is a critical vulnerability in Palo Alto PAN-OS User-ID Authentication Portal that allows unauthenticated attackers to execute arbitrary code with root privileges on PA-Series and VM-Series firewalls configured to use the portal, with limited exploitation observed.
date: "2026-05-06T08:44:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-0300
  - palo alto
  - pan-os
  - rce
  - network
vendors:
  - Palo Alto
products:
  - PA-Series
  - VM-Series
  - PAN-OS versions prior to 12.1.4-h5
  - PAN-OS versions prior to 12.1.7
  - PAN-OS versions prior to 11.2.4-h17
  - PAN-OS versions prior to 11.2.7-h13
  - PAN-OS versions prior to 11.2.10-h6
  - PAN-OS versions prior to 11.2.12
  - PAN-OS versions prior to 11.1.4-h33
  - PAN-OS versions prior to 11.1.6-h32
  - PAN-OS versions prior to 11.1.7-h6
  - PAN-OS versions prior to 11.1.10-h25
  - PAN-OS versions prior to 11.1.13-h5
  - PAN-OS versions prior to 11.1.15
  - PAN-OS versions prior to 10.2.7-h34
  - PAN-OS versions prior to 10.2.10-h36
  - PAN-OS versions prior to 10.2.13-h21
  - PAN-OS versions prior to 10.2.16-h7
  - PAN-OS versions prior to 10.2.18-h6
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://cert.europa.eu/publications/security-advisories/2026-006/
  - https://security.paloaltonetworks.com/CVE-2026-0300
iocs:
  - type: email
    value: services@cert.europa.eu
ioc_counts:
  email: 1
rules:
  - title: PAN-OS User-ID Authentication Portal Buffer Overflow Attempt
    description: Detects potential attempts to exploit the buffer overflow vulnerability (CVE-2026-0300) in the PAN-OS User-ID Authentication Portal by monitoring for unusual traffic patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - network_connection
      - windows
  - title: PAN-OS Emergency Contact Email
    description: Detects connections to the PAN-OS Emergency contact email
    platform: sigma
    severity: high
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On May 6, 2026, Palo Alto Networks disclosed CVE-2026-0300, a critical vulnerability affecting PAN-OS. This vulnerability is a buffer overflow located in the User-ID Authentication Portal (Captive Portal) service. Successful exploitation allows an unauthenticated attacker to execute arbitrary code with root privileges on affected PA-Series and VM-Series firewalls. The vulnerability impacts firewalls configured to utilize the User-ID Authentication Portal feature. Palo Alto Networks has noted limited exploitation of this vulnerability. Immediate patching is advised upon release, alongside implementing provided workarounds.

## Attack Chain

1.  The attacker identifies a vulnerable PA-Series or VM-Series firewall with the User-ID Authentication Portal enabled.
2.  The attacker crafts a malicious packet designed to exploit the buffer overflow in the User-ID Authentication Portal service.
3.  The attacker sends the specially crafted packet to the vulnerable firewall's User-ID Authentication Portal endpoint.
4.  The buffer overflow occurs, allowing the attacker to overwrite memory and inject malicious code.
5.  The injected code executes with root privileges on the firewall.
6.  The attacker establishes persistence on the firewall, potentially through creating a new user account or modifying system configurations.
7.  The attacker uses their root access to move laterally within the network or exfiltrate sensitive data.
8.  The attacker achieves their objective, which could include data theft, disruption of services, or further exploitation of internal systems.

## Impact

Successful exploitation of CVE-2026-0300 grants an unauthenticated attacker complete control over the affected Palo Alto Networks firewalls. This can lead to significant data breaches, disruption of network services, and the potential for lateral movement to other systems within the network. Given the role of firewalls in network security, a successful attack could compromise the entire protected network. Palo Alto Networks has reported limited exploitation, but the severity and ease of exploitation make this a high-priority vulnerability to address.

## Recommendation

*   Apply the security patches released by Palo Alto Networks as soon as they become available to remediate CVE-2026-0300.
*   Restrict User-ID Authentication Portal access to only trusted zones as a mitigation measure described in the advisory.
*   Disable the User-ID Authentication Portal if it is not required, as suggested in the advisory.
*   Monitor network traffic for unusual patterns targeting the User-ID Authentication Portal using network connection logs.
*   Deploy the Sigma rule "PAN-OS User-ID Authentication Portal Buffer Overflow Attempt" to detect potential exploitation attempts.
