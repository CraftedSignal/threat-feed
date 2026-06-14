---
title: strongSwan 5.9.13 Denial-of-Service Vulnerability (CVE-2026-35333)
slug: 2026-05-strongswan-dos
description: A denial-of-service vulnerability exists in strongSwan version 5.9.13 due to a flaw in the eap-radius plugin when built with DAE enabled, allowing remote attackers to exhaust worker threads by sending a crafted RADIUS Access-Request (CVE-2026-35333).
date: "2026-05-29T06:21:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - radius
  - strongswan
  - CVE-2026-35333
vendors:
  - strongSwan
products:
  - strongSwan <= 5.9.13
affected_os:
  - Debian 12
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://www.exploit-db.com/exploits/52586
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35333
  - https://github.com/strongswan/strongswan/commit/e067d24293
  - https://github.com/JohannesLks/CVE-2026-35333
rules:
  - title: Detect Strongswan CVE-2026-35333 DoS Exploit
    description: Detects CVE-2026-35333 exploitation - crafted RADIUS Access-Request packets with a zero-length User-Name attribute
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - zeek
  - title: Detect Strongswan CVE-2026-35333 High CPU Utilization
    description: Detects CVE-2026-35333 - High CPU usage by charon process indicating potential DoS
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_stats
      - linux
rules_count: 2
---

A denial-of-service (DoS) vulnerability has been identified in strongSwan version 5.9.13 (and earlier) within the eap-radius plugin when the DAE (Dead Anti-Exploit) feature is enabled. The vulnerability, tracked as CVE-2026-35333, stems from how the `attribute_enumerate()` function handles RADIUS messages with zero-length attributes. An attacker can exploit this flaw by sending a specially crafted RADIUS Access-Request containing a zero-length attribute. This triggers an infinite loop within the `charon` process, causing a worker thread to consume 100% CPU. Repeated exploitation can exhaust all available worker threads, effectively denying service to legitimate users. This vulnerability is pre-authentication, meaning an attacker does not need valid credentials to trigger the DoS. Public exploit code is available, increasing the urgency for patching vulnerable systems.

## Attack Chain

1.  The attacker identifies a strongSwan instance running version 5.9.13 or earlier with the eap-radius plugin and DAE enabled.
2.  The attacker crafts a malicious RADIUS Access-Request packet. The packet contains a User-Name attribute with a length of 0.
3.  The attacker sends the crafted RADIUS Access-Request packet to the strongSwan instance on UDP port 3799 (default).
4.  The `charon` daemon receives the packet and processes it via the `attribute_enumerate()` function in `src/libradius/radius_message.c`.
5.  Due to the zero-length attribute, the `attribute_enumerate()` function enters an infinite loop, causing a single `charon` worker thread to consume 100% CPU.
6.  The attacker sends multiple crafted packets to exhaust all available `charon` worker threads.
7.  Legitimate RADIUS authentication requests are no longer processed due to the exhaustion of worker threads.
8.  The strongSwan service becomes unavailable, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-35333 results in a denial-of-service condition, rendering the strongSwan VPN service unavailable. This can disrupt network access for legitimate users and impact business operations. The vulnerability is pre-authentication, meaning that anyone can trigger the DoS without requiring credentials. There is currently no information available regarding specific sectors targeted or the number of victims affected.

## Recommendation

*   Upgrade to a patched version of strongSwan that addresses CVE-2026-35333 to remediate the vulnerability.
*   Disable the `charon.plugins.eap-radius.dae.enable` option in the `strongswan.conf` file as a temporary workaround to mitigate the DoS, as shown in the exploit description.
*   Monitor strongSwan servers for high CPU utilization by `charon` worker threads using tools like `ps` to detect potential exploitation attempts.
*   Deploy the Sigma rule "Detect Strongswan CVE-2026-35333 DoS Exploit" to identify malicious RADIUS packets targeting the vulnerability in network traffic.
