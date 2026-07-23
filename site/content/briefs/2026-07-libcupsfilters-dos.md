---
title: 'CVE-2026-64611: libcupsfilters Denial of Service via Malformed Printer Advertisement'
slug: 2026-07-libcupsfilters-dos
description: A high-severity denial of service vulnerability, CVE-2026-64611, exists in the `cfIEEE1284NormalizeMakeModel()` function of libcupsfilters, allowing a network-adjacent attacker to cause sustained CPU consumption and system unresponsiveness by broadcasting a specially crafted printer advertisement with an empty model field in the IEEE-1284 device ID.
date: "2026-07-23T11:18:52Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - vulnerability
  - denial-of-service
  - linux
  - printer-vulnerability
vendors:
  - Red Hat
  - OpenPrinting
products:
  - libcupsfilters
  - cups-filters
  - Red Hat Enterprise Linux 10
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
affected_os:
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
  - Red Hat Enterprise Linux 10
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A network-adjacent attacker could exploit this by broadcasting a specially crafted printer advertisement, leading to denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-64611
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64611
  - https://access.redhat.com/security/cve/CVE-2026-64611
  - https://bugzilla.redhat.com/show_bug.cgi?id=2502799
  - https://github.com/OpenPrinting/libcupsfilters/security/advisories/GHSA-rcq7-rv5g-j3r4
---

A significant denial of service vulnerability, identified as CVE-2026-64611, has been discovered in the `libcupsfilters` library, specifically within the `cfIEEE1284NormalizeMakeModel()` function. This flaw allows a network-adjacent attacker to trigger an infinite loop by transmitting a specially crafted printer advertisement. The vulnerability is activated when the `libcupsfilters` component processes an IEEE-1284 device ID that includes an empty model field. This processing error leads to sustained CPU consumption on the affected system, effectively rendering the printing services or the entire system unresponsive. The bug is critical for environments where `libcupsfilters` is used, particularly Red Hat Enterprise Linux systems. This vulnerability highlights the importance of input validation in network-facing services and the potential for seemingly innocuous data fields to be exploited for resource exhaustion.

## Attack Chain

1. A network-adjacent attacker gains access to the same local network segment as the vulnerable system running `libcupsfilters`.
2. The attacker broadcasts a specially crafted printer advertisement packet on the network.
3. This advertisement includes an IEEE-1284 device ID containing an empty model field, deviating from expected specifications.
4. The vulnerable system, using `libcupsfilters`, receives and attempts to process this malformed printer advertisement.
5. Specifically, the `cfIEEE1284NormalizeMakeModel()` function within `libcupsfilters` is invoked to handle the IEEE-1284 device ID.
6. Due to the empty model field, the `cfIEEE1284NormalizeMakeModel()` function enters an infinite loop, consuming all available CPU resources.
7. The sustained CPU consumption leads to a denial of service condition, making the system or its printing services unresponsive.

## Impact

Successful exploitation of CVE-2026-64611 results in a complete denial of service for systems running `libcupsfilters`, such as Red Hat Enterprise Linux 7, 8, 9, and 10. The infinite loop triggered by a malformed printer advertisement causes sustained and maximum CPU utilization, preventing legitimate users or services from accessing system resources. This could lead to significant operational disruptions, loss of data processing capabilities for printing-related tasks, and potential service outages in affected organizations. While no specific victim counts are provided, any organization utilizing the vulnerable `libcupsfilters` versions within a network where an attacker can send printer advertisements is at risk.

## Recommendation

* Patch CVE-2026-64611 immediately on all affected Red Hat Enterprise Linux systems to mitigate the denial of service vulnerability.
* Monitor network traffic for unusual or malformed printer advertisement broadcasts, though specific signatures may be difficult to define without further details on the crafted packets.
* Review network segmentation to limit the reach of network-adjacent attackers to critical systems that utilize `libcupsfilters`.
