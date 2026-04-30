---
title: Dnsmasq Out-of-Bounds Write Vulnerability (CVE-2026-6507)
slug: 2026-04-dnsmasq-dos
description: A remote attacker can exploit an out-of-bounds write vulnerability (CVE-2026-6507) in dnsmasq by sending a specially crafted BOOTREPLY packet to a server configured with the `--dhcp-split-relay` option, leading to a denial of service.
date: "2026-04-17T13:16:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dnsmasq
  - denial-of-service
  - cve-2026-6507
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2026-6507
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6507
  - https://access.redhat.com/security/cve/CVE-2026-6507
  - https://bugzilla.redhat.com/show_bug.cgi?id=2459181
rules:
  - title: Detect Malformed BOOTREPLY Packets
    description: Detects suspicious BOOTREPLY packets that may be crafted to exploit CVE-2026-6507
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Dnsmasq Process Crash
    description: Detects dnsmasq process crashes, which could indicate exploitation of CVE-2026-6507
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-6507 is an out-of-bounds write vulnerability affecting dnsmasq. The vulnerability is triggered when a dnsmasq server is configured with the `--dhcp-split-relay` option and receives a specially crafted BOOTREPLY packet from a remote attacker. Successful exploitation results in memory corruption, causing the dnsmasq daemon to crash and leading to a denial of service (DoS) condition. This vulnerability poses a significant threat to organizations relying on dnsmasq for DNS and DHCP services, potentially disrupting network connectivity and availability. The vulnerability was reported on April 17, 2026.

## Attack Chain

1.  Attacker identifies a target dnsmasq server running with the `--dhcp-split-relay` option enabled.
2.  Attacker crafts a malicious BOOTREPLY packet specifically designed to trigger the out-of-bounds write vulnerability.
3.  The attacker sends the crafted BOOTREPLY packet to the targeted dnsmasq server.
4.  The dnsmasq server processes the malicious packet, leading to an out-of-bounds write in memory.
5.  Memory corruption occurs due to the out-of-bounds write.
6.  The dnsmasq daemon encounters a critical error due to the memory corruption.
7.  The dnsmasq daemon crashes, interrupting DNS and DHCP services.
8.  Legitimate clients are unable to resolve domain names or obtain IP addresses, resulting in a denial of service.

## Impact

Successful exploitation of CVE-2026-6507 leads to a denial-of-service condition, disrupting network connectivity and potentially affecting all clients relying on the vulnerable dnsmasq server for DNS and DHCP services. The impact ranges from temporary network outages to complete service unavailability, depending on the criticality of the affected dnsmasq instance. The number of affected systems will vary based on the prevalence of dnsmasq deployments with the `--dhcp-split-relay` option enabled.

## Recommendation

*   Apply the patch or upgrade to a non-vulnerable version of dnsmasq as provided by the vendor to remediate CVE-2026-6507 (https://nvd.nist.gov/vuln/detail/CVE-2026-6507).
*   Disable the `--dhcp-split-relay` option in dnsmasq configuration if it is not required, mitigating the attack vector (https://nvd.nist.gov/vuln/detail/CVE-2026-6507).
*   Monitor network traffic for malformed BOOTREPLY packets targeting dnsmasq servers, using the "Detect Malformed BOOTREPLY Packets" Sigma rule.
*   Enable process crash monitoring on systems running dnsmasq to detect potential crashes resulting from exploitation attempts, using the "Detect Dnsmasq Process Crash" Sigma rule.
