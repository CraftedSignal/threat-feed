---
title: GoBGP AIGP Attribute Parser Buffer Overflow Vulnerability
slug: 2026-05-gobgp-buffer-overflow
description: A remote buffer overflow vulnerability exists in osrg GoBGP up to version 4.3.0 within the PathAttributeAigp.DecodeFromBytes function, allowing attackers to potentially execute arbitrary code by manipulating the AIGP Attribute Parser.
date: "2026-05-04T06:16:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-7735
  - buffer-overflow
  - bgp
vendors:
  - osrg
products:
  - GoBGP (<= 4.3.0)
cves:
  - id: CVE-2026-7735
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7735
  - https://github.com/osrg/gobgp/
  - https://github.com/osrg/gobgp/commit/51ad1ada06cb41ce47b7066799981816f50b7ced
  - https://github.com/osrg/gobgp/releases/tag/v4.4.0
  - https://vuldb.com/submit/807600
  - https://vuldb.com/vuln/360910
  - https://vuldb.com/vuln/360910/cti
rules:
  - title: Detect Connection Attempts to BGP Port from Unusual Sources
    description: Detects connection attempts to the BGP port (179) from IP addresses not in the known BGP peers list.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect large packets to BGP port
    description: Detects unusually large network packets to BGP port which could indicate an attempt to overflow buffer
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A buffer overflow vulnerability has been identified in the osrg GoBGP software, specifically affecting versions up to 4.3.0. The vulnerability resides in the `PathAttributeAigp.DecodeFromBytes` function of the `pkg/packet/bgp/bgp.go` file, which is part of the AIGP Attribute Parser component. An attacker can remotely trigger this vulnerability by sending a crafted BGP message containing a malicious AIGP attribute. Successful exploitation could lead to arbitrary code execution on the affected system. GoBGP is an open source BGP implementation. Organizations using GoBGP for routing purposes should upgrade to version 4.4.0 or apply the provided patch (51ad1ada06cb41ce47b7066799981816f50b7ced) to mitigate this risk.

## Attack Chain

1.  Attacker identifies a GoBGP instance running a vulnerable version (<= 4.3.0).
2.  Attacker crafts a malicious BGP update message containing a specially crafted AIGP attribute.
3.  The crafted AIGP attribute is designed to trigger a buffer overflow in the `PathAttributeAigp.DecodeFromBytes` function.
4.  The attacker sends the malicious BGP update message to the vulnerable GoBGP instance over TCP port 179.
5.  The GoBGP instance receives the message and attempts to parse the AIGP attribute using the vulnerable function.
6.  The `PathAttributeAigp.DecodeFromBytes` function fails to properly validate the size of the input data, leading to a buffer overflow.
7.  The buffer overflow overwrites adjacent memory regions, potentially including critical program data or executable code.
8.  The attacker leverages the memory corruption to execute arbitrary code on the GoBGP instance, gaining control of the system.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the affected GoBGP instance. This can lead to a complete compromise of the routing infrastructure, allowing the attacker to intercept, modify, or disrupt network traffic. In service provider environments, this could affect a large number of customers and cause significant network outages. Given the CVSS v3.1 score of 7.3, this is considered a high-severity vulnerability.

## Recommendation

*   Upgrade to GoBGP version 4.4.0 to remediate the vulnerability as mentioned in the overview.
*   Apply the patch `51ad1ada06cb41ce47b7066799981816f50b7ced` to the affected component to mitigate the vulnerability if upgrading is not immediately possible.
*   Monitor network traffic for BGP update messages with unusually large or malformed AIGP attributes, using a network intrusion detection system.
*   Deploy the Sigma rule detecting connections to port 179 from unusual sources to identify potentially malicious hosts attempting to exploit the vulnerability.
*   Review and harden BGP configuration to limit accepted peer connections to trusted sources only.
