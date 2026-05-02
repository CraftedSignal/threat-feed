---
title: MikroTik RouterOS SCEP Endpoint Out-of-Bounds Read Vulnerability (CVE-2026-7668)
slug: 2024-01-routeros-oob-read
description: MikroTik RouterOS 6.49.8 is vulnerable to an out-of-bounds read in the SCEP endpoint component, triggered by remote manipulation of the transactionID/messageType argument, potentially leading to denial of service or information disclosure.
date: "2024-01-02T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - out-of-bounds read
  - routeros
vendors:
  - MikroTik
products:
  - RouterOS (6.49.8)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-7668
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7668
rules:
  - title: Detect Malformed SCEP Requests via Network Traffic
    description: Detects network connections with unusual SCEP requests, potentially indicating exploitation attempts against CVE-2026-7668.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - zeek
  - title: Detect Abnormal Process Executions Related to SCEP Endpoint
    description: Detects potential exploitation of CVE-2026-7668 by monitoring for unusual process executions originating from or related to the SCEP endpoint.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-7668 is an out-of-bounds read vulnerability affecting MikroTik RouterOS version 6.49.8. The vulnerability exists within the SCEP (Simple Certificate Enrollment Protocol) endpoint, specifically in the `ASN1_STRING_data` function located in the `nova/lib/www/scep.p` library. A remote attacker can exploit this vulnerability by manipulating the `transactionID` or `messageType` arguments. Publicly available exploits exist, increasing the risk of exploitation. The vendor has been notified but has not provided a response. Exploitation could lead to denial of service or information disclosure.

## Attack Chain

1.  Attacker identifies a MikroTik RouterOS device running version 6.49.8 with an exposed SCEP endpoint.
2.  The attacker crafts a malicious SCEP request containing a specially crafted `transactionID` or `messageType` argument.
3.  The attacker sends the malicious SCEP request to the RouterOS device's SCEP endpoint.
4.  The `ASN1_STRING_data` function processes the request and attempts to access memory outside the allocated buffer due to the manipulated argument.
5.  The out-of-bounds read occurs, potentially leading to a crash of the SCEP process or the disclosure of sensitive information from adjacent memory regions.
6.  If the attacker can reliably trigger a crash, they can cause a denial of service.
7.  If sensitive information is disclosed, the attacker might use this to further compromise the device or network.

## Impact

Successful exploitation of CVE-2026-7668 can lead to a denial of service condition on the affected MikroTik RouterOS device. An attacker could potentially cause the device to become unresponsive, disrupting network services. Furthermore, the out-of-bounds read could expose sensitive information stored in memory, which an attacker could use to further compromise the device or network. Since an exploit is publicly available, the risk of widespread exploitation is elevated.

## Recommendation

*   Monitor network traffic for SCEP requests with unusually long or malformed `transactionID` or `messageType` parameters. Use the network connection rule below.
*   Implement rate limiting on the SCEP endpoint to mitigate potential denial-of-service attacks.
*   While no patch is available, consider disabling the SCEP endpoint if it is not required.
