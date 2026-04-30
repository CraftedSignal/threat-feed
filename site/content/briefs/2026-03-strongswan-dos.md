---
title: strongSwan EAP-TTLS AVP Integer Underflow Vulnerability (CVE-2026-25075)
slug: 2026-03-strongswan-dos
description: An integer underflow vulnerability in strongSwan's EAP-TTLS AVP parser allows unauthenticated remote attackers to cause a denial of service by sending crafted AVP data with invalid length fields during IKEv2 authentication, leading to excessive memory allocation or a NULL pointer dereference.
date: "2026-03-24T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - denial-of-service
  - integer-underflow
  - strongSwan
  - CVE-2026-25075
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25075
  - https://www.strongswan.org/blog/2026/03/23/strongswan-6.0.5-released.html
  - https://www.strongswan.org/blog/2026/03/23/strongswan-vulnerability-(cve-2026-25075).html
  - https://www.vulncheck.com/advisories/strongswan-eap-ttls-avp-parsing-integer-underflow
rules:
  - title: Detect strongSwan Charon Process Crash
    description: Detects crashes of the charon IKE daemon which might indicate CVE-2026-25075 exploitation
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - system
      - linux
  - title: Detect Excessive Memory Allocation in strongSwan
    description: Detects potential exploitation of CVE-2026-25075 by monitoring memory allocation errors in charon logs.
    platform: sigma
    severity: medium
    tactics:
      - resource_hijacking
    techniques:
      - T1496
    data_sources:
      - system
      - linux
rules_count: 2
---

The strongSwan VPN suite is susceptible to an integer underflow vulnerability (CVE-2026-25075) affecting versions 4.5.0 up to 6.0.4. This flaw resides within the EAP-TTLS AVP (Attribute Value Pair) parser. A remote, unauthenticated attacker can exploit this vulnerability by sending specifically crafted AVP data during the IKEv2 (Internet Key Exchange version 2) authentication process. Successful exploitation leads to a denial-of-service condition due to excessive memory allocation or a NULL…
