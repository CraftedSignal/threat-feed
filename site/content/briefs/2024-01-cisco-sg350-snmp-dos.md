---
title: Cisco SG350 and SG350X Series Managed Switches SNMP Denial-of-Service Vulnerability
slug: 2024-01-cisco-sg350-snmp-dos
description: A remote, authenticated attacker can cause a denial-of-service condition on vulnerable Cisco SG350 and SG350X Series Managed Switches by sending a crafted SNMP request due to improper error handling.
date: "2026-05-06T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - snmp
  - denial-of-service
  - cve-2026-20185
vendors:
  - Cisco
products:
  - SG350 Series Managed Switches
  - SG350X Series Stackable Managed Switches
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sg350-snmp-dos-GEFZr2Tj?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20SG350%20and%20SG350X%20Series%20Managed%20Switches%20SNMP%20Denial%20of%20Service%20Vulnerability%26vs_k=1
rules:
  - title: Detect SNMP Traffic from Uncommon Source IPs
    description: Detects SNMP traffic originating from source IPs not commonly associated with SNMP management.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - network_connection
      - windows
  - title: Detect High Volume SNMP Traffic to Port 161
    description: Detects a high volume of UDP traffic to destination port 161 (SNMP), which may indicate a DoS attempt.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A vulnerability exists in the Simple Network Management Protocol (SNMP) subsystem of Cisco 350 Series Managed Switches (SG350) and Cisco 350X Series Stackable Managed Switches (SG350X). The flaw, identified as CVE-2026-20185, stems from improper error handling during the parsing of response data related to a specific SNMP request. To exploit this vulnerability via SNMPv2c or earlier, an attacker needs to know a valid read-write or read-only SNMP community string for the affected system. For SNMPv3 exploitation, valid SNMP user credentials are required. Cisco will not release software updates to address this vulnerability because the affected products are past their End of Software Maintenance Releases date.

## Attack Chain

1.  The attacker authenticates to the target switch via SNMP using valid credentials or community string.
2.  The attacker crafts a specific SNMP request designed to trigger the vulnerability.
3.  The attacker sends the malicious SNMP request to the targeted device.
4.  The device processes the SNMP request, and due to improper error handling, a parsing error occurs.
5.  The parsing error causes the SNMP subsystem to enter an unstable state.
6.  The device attempts to recover from the error, but the severity of the error triggers a system reload.
7.  The switch unexpectedly reloads, causing a denial-of-service condition.
8.  Network services reliant on the switch's functionality become unavailable until the device completes its reboot process.

## Impact

Successful exploitation of this vulnerability results in an unexpected device reload, leading to a denial-of-service condition. Any network services relying on the affected Cisco SG350 or SG350X series switch will be temporarily unavailable. The duration of the outage depends on the time it takes for the switch to reboot. Organizations using these switches may experience network disruptions impacting business operations.

## Recommendation

*   Since Cisco will not be releasing patches for this vulnerability, implement access control lists to restrict SNMP access to only trusted hosts, mitigating the risk of unauthorized exploitation of CVE-2026-20185.
*   Monitor network traffic for suspicious SNMP requests, especially those originating from untrusted sources.
*   Disable SNMP versions 1, 2c, and 3 if not in use to reduce the attack surface.
