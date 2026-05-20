---
title: Wireshark Remote Denial of Service Vulnerability
slug: 2026-05-wireshark-dos
description: A vulnerability in Wireshark versions 4.4.x before 4.4.16 and 4.6.x before 4.6.6 allows a remote attacker to cause a denial of service.
date: "2026-05-20T14:07:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - wireshark
vendors:
  - Wireshark
products:
  - Wireshark 4.4.x
  - Wireshark 4.6.x
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0616/
  - https://www.wireshark.org/security/wnpa-sec-2026-51.html
rules:
  - title: Detect Wireshark Unexpected Termination
    description: Detects unexpected termination of Wireshark process which may indicate denial-of-service exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Wireshark Unexpected Termination (Linux)
    description: Detects unexpected termination of Wireshark process which may indicate denial-of-service exploitation on Linux.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in Wireshark, as detailed in the Wireshark security bulletin wnpa-sec-2026-51 published on May 20, 2026. This flaw affects Wireshark versions 4.4.x prior to 4.4.16 and 4.6.x prior to 4.6.6. An attacker could exploit this vulnerability to remotely disrupt the normal functioning of Wireshark, potentially hindering network analysis and monitoring activities. This vulnerability is important for defenders because Wireshark is a widely used tool for network traffic analysis, and its unavailability can impact incident response and network troubleshooting capabilities.

## Attack Chain

1.  The attacker crafts a malicious network packet.
2.  The attacker sends the malicious packet to a system running a vulnerable version of Wireshark.
3.  Wireshark attempts to dissect the malformed packet.
4.  The vulnerability within the packet dissection logic is triggered.
5.  Wireshark enters a faulty state, such as an infinite loop or excessive memory consumption.
6.  Wireshark's processing becomes unresponsive.
7.  Wireshark becomes unavailable, denying service to legitimate users.

## Impact

Successful exploitation of this vulnerability results in a denial of service, rendering Wireshark unusable. This can disrupt network analysis tasks, hinder incident response efforts, and prevent network administrators from monitoring and troubleshooting network issues. The vulnerability affects organizations that rely on Wireshark for network traffic analysis, impacting their ability to maintain network visibility and security.

## Recommendation

*   Upgrade Wireshark to version 4.4.16 or later, or to version 4.6.6 or later to remediate the vulnerability as per Wireshark security bulletin wnpa-sec-2026-51.
*   Monitor network traffic for unexpected patterns or malformed packets that may indicate a denial-of-service attempt targeting Wireshark.
*   Deploy the Sigma rule to detect potential exploitation attempts by identifying abnormal Wireshark process termination.
