---
title: CVE-2026-57026 - Improper Validation of SIP Input in Juniper Junos OS Leads to DoS
slug: 2026-07-juniper-junos-sip-dos
description: An unauthenticated, network-based attacker can exploit CVE-2026-57026, an improper input validation vulnerability, in the SIP plugin of Juniper Networks Junos OS. If the SIP ALG is enabled on affected MX Series with SPC3 or SRX Series devices, processing a malformed SIP invite packet will cause the flow processing daemon (flowd) to crash and restart, leading to a complete denial of service until the system recovers.
date: "2026-07-09T22:21:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - juniper
  - network
vendors:
  - Juniper Networks
products:
  - Junos OS on MX Series with SPC3 (all versions before 23.2R2-S7)
  - Junos OS on MX Series with SPC3 (23.4 versions before 23.4R2-S8)
  - Junos OS on MX Series with SPC3 (24.2 versions before 24.2R2-S5)
  - Junos OS on MX Series with SPC3 (24.4 versions before 24.4R2-S4)
  - Junos OS on MX Series with SPC3 (25.2 versions before 25.2R2)
  - Junos OS on MX Series with SPC3 (25.4 versions before 25.4R1-S2)
  - Junos OS on SRX Series (all versions before 23.2R2-S7)
  - Junos OS on SRX Series (23.4 versions before 23.4R2-S8)
  - Junos OS on SRX Series (24.2 versions before 24.2R2-S5)
  - Junos OS on SRX Series (24.4 versions before 24.4R2-S4)
  - Junos OS on SRX Series (25.2 versions before 25.2R2)
  - Junos OS on SRX Series (25.4 versions before 25.4R1-S2)
affected_os:
  - Junos OS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: processing of a malformed SIP invite packet will cause a flow processing daemon (flowd) crash and restart. This leads to a complete service outage until the system has automatically recovered.
    confidence_band: high
cves:
  - id: CVE-2026-57026
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57026
---

A critical denial-of-service vulnerability, CVE-2026-57026, has been identified in Juniper Networks Junos OS, affecting MX Series devices equipped with SPC3 line cards and SRX Series firewalls. This flaw resides within the SIP plugin, specifically when the SIP Application Layer Gateway (ALG) feature is enabled. An unauthenticated attacker, operating over the network, can exploit this vulnerability by sending a specially crafted, malformed SIP INVITE packet to a vulnerable device. The improper validation of syntactic correctness within the SIP plugin causes the device's flow processing daemon (`flowd`) to crash and restart. This event triggers a complete service outage, rendering the device inoperable until it automatically recovers, making it a significant concern for network availability and stability. All versions before 23.2R2-S7, and specific versions across 23.4, 24.2, 24.4, 25.2, and 25.4 releases are affected.

## Attack Chain

1. **Target Identification**: An unauthenticated attacker identifies a Juniper Networks MX Series device with SPC3 or an SRX Series device running a vulnerable version of Junos OS, with the SIP ALG feature enabled and reachable over the network.
2. **Packet Crafting**: The attacker constructs a malformed SIP INVITE packet, specifically designed to exploit the improper input validation vulnerability within the device's SIP plugin.
3. **Exploitation Attempt**: The crafted malformed SIP INVITE packet is sent by the attacker to the vulnerable Juniper device.
4. **Vulnerability Trigger**: The device, with its SIP ALG enabled, attempts to process the syntactically incorrect SIP INVITE packet.
5. **Daemon Crash**: Due to the improper validation, the processing of the malformed packet causes the `flowd` (flow processing daemon) on the Juniper device to crash.
6. **Service Outage**: The `flowd` crash immediately results in a complete denial-of-service, leading to a network outage and disruption of traffic flow through the affected device.
7. **System Recovery (Temporary)**: The device automatically initiates a restart of the `flowd` daemon and recovers its services, but remains vulnerable to repeated exploitation.

## Impact

The successful exploitation of CVE-2026-57026 leads directly to a complete denial-of-service (DoS) for the affected Juniper Networks device. This means that all network services routed through the compromised MX Series with SPC3 or SRX Series device will become unavailable, causing significant operational disruption. The `flowd` crash and subsequent restart, while automatic, represents a critical availability risk, especially for organizations relying on these devices for core network routing and security functions. The unauthenticated and network-based nature of the attack allows for widespread impact without prior access or credentials, affecting any internet-facing or internally exposed vulnerable device.

## Recommendation

* Immediately apply the security updates for CVE-2026-57026 provided by Juniper Networks to all affected Junos OS on MX Series with SPC3 and SRX Series devices.
* Review network configurations for all devices identified as affected in this brief, and disable the SIP ALG feature if it is not explicitly required for your network's voice or multimedia services.
* Monitor your Juniper Networks MX Series and SRX Series devices for unexpected `flowd` crashes or restarts as a potential indicator of CVE-2026-57026 exploitation attempts.
