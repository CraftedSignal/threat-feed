---
title: Juniper Networks Releases Security Advisories for Multiple Vulnerabilities, Including Heap Buffer Overflow and Memory Leak
slug: 2026-07-juniper-networks-vulnerabilities
description: Juniper Networks has released security advisories to address multiple vulnerabilities across several products, including Juniper cRPD, CTPView, Network Director, Junos OS, Junos OS Evolved, Junos OS on MX Series with SPC3 and SRX Series, and Junos Space, with key vulnerabilities like a heap buffer overflow (CVE-2020-7450) and a memory leak (CVE-2026-33799) potentially leading to arbitrary code execution or denial of service.
date: "2026-07-08T18:01:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:freebsd:freebsd:11.3:-:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:11.3:p1:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:11.3:p2:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:11.3:p3:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:11.3:p4:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:11.3:p5:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:-:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p1:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p10:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p11:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p12:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p2:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p3:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p4:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p6:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p7:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p8:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.0:p9:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.1:-:*:*:*:*:*:*
  - cpe:2.3:o:freebsd:freebsd:12.1:p1:*:*:*:*:*:*
tags:
  - vulnerability
  - network-device
  - juniper
  - patch-management
vendors:
  - Juniper Networks
products:
  - Juniper cRPD
  - Juniper CTPView < 9.3R2-3
  - Juniper Network Director < 7.1R3
  - Junos OS
  - Junos OS Evolved
  - Junos OS on MX Series with SPC3 and SRX Series
  - Junos Space < 26.1R1 Patch V1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: URL handling vulnerability in libfetch results in heap buffer overflow (CVE-2020-7450)
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Receipt of a specific SNMPv3 request results in memory leak and eventual snmpd crash (CVE-2026-33799)
    confidence_band: high
cves:
  - id: CVE-2020-7450
    cvss: 9.8
    epss: 0.02494
references:
  - https://cyber.gc.ca/en/alerts-advisories/juniper-networks-security-advisory-av26-675
  - https://supportportal.juniper.net/s/article/2026-07-Security-Bulletin-CTPView-Multiple-vulnerabilities-resolved-in-9-3R2-3-Release
  - https://supportportal.juniper.net/s/article/2026-07-Security-Bulletin-Junos-Space-Multiple-vulnerabilities-resolved-in-26-1R1-Patch-V1-Release
  - https://supportportal.juniper.net/s/article/2026-07-Security-Bulletin-Junos-OS-Evolved-URL-handling-vulnerability-in-libfetch-results-in-heap-buffer-overflow-CVE-2020-7450
  - https://supportportal.juniper.net/s/article/2026-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Receipt-of-a-specific-SNMPv3-request-results-in-memory-leak-and-eventual-snmpd-crash-CVE-2026-33799
  - https://supportportal.juniper.net/s/global-search/%40uri#f-sf_primarysourcename=Knowledge
---

On July 8, 2026, Juniper Networks published security advisories to address critical vulnerabilities affecting a wide range of its networking products. The advisories highlight issues in Juniper cRPD, CTPView, Network Director, Junos OS, Junos OS Evolved, Junos OS on MX Series with SPC3 and SRX Series, and Junos Space. Two notable vulnerabilities are CVE-2020-7450, a heap buffer overflow in the `libfetch` component of Junos OS Evolved, and CVE-2026-33799, a memory leak in the `snmpd` daemon affecting both Junos OS and Junos OS Evolved. These flaws could be exploited by remote attackers, potentially leading to arbitrary code execution or denial of service on affected devices. Organizations using Juniper products are strongly urged to review the advisories and apply the necessary updates to mitigate these risks.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing Juniper Networks devices running vulnerable versions of Junos OS or Junos OS Evolved.
2. **For CVE-2020-7450 (Junos OS Evolved):** The attacker crafts and sends a malicious HTTP/HTTPS request containing a specially malformed URL to the target device.
3. The vulnerable `libfetch` component within Junos OS Evolved attempts to parse the malformed URL, triggering a heap buffer overflow condition.
4. This heap buffer overflow can be exploited by the attacker to achieve arbitrary code execution on the device, potentially leading to full system compromise.
5. **For CVE-2026-33799 (Junos OS/Evolved):** The attacker crafts and sends a specific, malformed SNMPv3 request to the vulnerable Juniper device.
6. The `snmpd` daemon on the device processes the crafted SNMPv3 request, which results in a memory leak within the daemon's allocated memory space.
7. The attacker continuously sends repeated crafted SNMPv3 requests, causing further memory leaks and gradually depleting the `snmpd` daemon's resources.
8. Eventually, the persistent memory exhaustion causes the `snmpd` daemon to crash, leading to a Denial of Service for SNMP services on the affected Juniper device.

## Impact

The identified vulnerabilities pose significant risks to network infrastructure. Exploitation of CVE-2020-7450, a heap buffer overflow, could allow an unauthenticated attacker to achieve arbitrary code execution on Junos OS Evolved devices. This would grant the attacker full control over the device, enabling data exfiltration, network segmentation bypass, or further compromise of the internal network. CVE-2026-33799, a memory leak, can lead to a denial of service for SNMP services on both Junos OS and Junos OS Evolved. While not directly leading to system compromise, a crashed SNMP daemon can disrupt network monitoring, management, and potentially impact other critical services reliant on SNMP, leading to operational downtime and reduced visibility into network health.

## Recommendation

* Immediately apply the recommended updates and patches provided by Juniper Networks for all affected products as detailed in the Juniper Networks security advisories linked in this brief.
* Ensure that internet-facing Junos OS Evolved devices are patched against CVE-2020-7450 to prevent potential arbitrary code execution.
* Verify that Junos OS and Junos OS Evolved devices are updated to mitigate CVE-2026-33799 and prevent SNMP service denial of service.
* Review the specific security bulletins (e.g., "2026-07 Security Bulletin: CTPView: Multiple vulnerabilities resolved in 9.3R2-3 Release", "2026-07 Security Bulletin: Junos Space: Multiple vulnerabilities resolved in 26.1R1 Patch V1 Release") for precise version requirements and update paths.
