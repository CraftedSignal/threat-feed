---
title: BusyBox DHCPv6 Client Heap Buffer Overflow Vulnerability (CVE-2026-29004)
slug: 2026-05-busybox-dhcpv6-overflow
description: A heap buffer overflow vulnerability in BusyBox's DHCPv6 client allows network-adjacent attackers to trigger memory corruption, denial of service, or arbitrary code execution via crafted DHCPv6 responses.
date: "2026-05-04T18:16:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - heap-overflow
  - dhcpv6
  - busybox
  - cve-2026-29004
  - denial-of-service
vendors:
  - BusyBox
products:
  - BusyBox
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: 'Endpoint Denial of Service: Memory Exhaustion'
cves:
  - id: CVE-2026-29004
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29004
rules:
  - title: Detect Suspicious DHCPv6 DNS Server Option Size
    description: Detects DHCPv6 responses with unusually large DNS server option sizes, potentially indicating an attempted heap overflow exploit.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
  - title: Detect DHCPv6 Client Process
    description: Detects execution of the DHCPv6 client udhcpc6, which may be legitimate but warrants monitoring.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-29004 is a critical heap buffer overflow vulnerability affecting BusyBox before commit 42202bf. The vulnerability resides in the DHCPv6 client (udhcpc6), specifically within the DNS_SERVERS option handler located in networking/udhcp/d6_dhcpc.c. A network-adjacent attacker can exploit this flaw by sending a malicious DHCPv6 response containing a malformed D6_OPT_DNS_SERVERS option. This manipulation leads to incorrect heap buffer allocation calculations in the option_to_env() function, causing memory corruption. Successful exploitation can result in a denial of service or, more severely, arbitrary code execution on vulnerable embedded systems lacking heap hardening. The scope of impact is potentially broad, given BusyBox's widespread use in embedded devices.

## Attack Chain

1. Attacker identifies a target embedded system running a vulnerable version of BusyBox with the DHCPv6 client enabled.
2. The attacker crafts a malicious DHCPv6 response packet.
3. The crafted packet includes a D6_OPT_DNS_SERVERS option with a size that exceeds the expected buffer allocation.
4. The attacker transmits the crafted DHCPv6 response packet to the target system on the local network.
5. The target system's udhcpc6 client receives the malicious DHCPv6 response.
6. The udhcpc6 client processes the D6_OPT_DNS_SERVERS option, triggering the vulnerable option_to_env() function.
7. The option_to_env() function calculates an insufficient buffer size based on the malformed option.
8. A heap buffer overflow occurs when copying the oversized DNS server list, leading to memory corruption, denial-of-service, or arbitrary code execution.

## Impact

Successful exploitation of CVE-2026-29004 can have severe consequences. A denial-of-service condition could disrupt the functionality of the affected embedded system. More critically, arbitrary code execution allows attackers to gain complete control over the device, potentially leading to data theft, device compromise, or use in botnet activities. Given BusyBox's prevalence in embedded systems, a large number of devices are potentially vulnerable.

## Recommendation

*   Apply the patch addressing CVE-2026-29004 by updating to a version of BusyBox after commit 42202bf.
*   Deploy the Sigma rule "Detect Suspicious DHCPv6 DNS Server Option Size" to identify potentially malicious DHCPv6 responses in network traffic.
*   Monitor network traffic for unusually large DHCPv6 DNS_SERVERS options as indicated by the Sigma rule and network connection logs.
