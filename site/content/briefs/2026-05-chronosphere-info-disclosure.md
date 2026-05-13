---
title: CVE-2026-0239 Chronosphere Chronocollector Information Disclosure Vulnerability
slug: 2026-05-chronosphere-info-disclosure
description: CVE-2026-0239 is an information disclosure vulnerability in Chronosphere Chronocollector versions earlier than v0.116.0, allowing an unauthenticated attacker with network access to retrieve sensitive information.
date: "2026-05-13T16:06:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - information disclosure
  - vulnerability
  - network
vendors:
  - Palo Alto Networks
  - Chronosphere
products:
  - Chronosphere Chronocollector < v0.116.0
references:
  - https://security.paloaltonetworks.com/CVE-2026-0239
  - CVE-2026-0239
rules:
  - title: Detect CVE-2026-0239 Exploitation Attempt - Chronosphere Chronocollector Information Disclosure
    description: Detects potential exploitation attempts of CVE-2026-0239, targeting Chronosphere Chronocollector, by monitoring for suspicious network requests.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

CVE-2026-0239 is an information disclosure vulnerability affecting Chronosphere Chronocollector versions prior to v0.116.0. This vulnerability allows an unauthenticated attacker with network access to the Chronocollector service to retrieve sensitive information. No special configuration is required for a Chronosphere Chronocollector instance to be vulnerable. Palo Alto Networks internally discovered and reported this issue. Successful exploitation could lead to the exposure of sensitive system information.

## Attack Chain

1.  Attacker gains network access to the Chronosphere Chronocollector service.
2.  Attacker sends a specially crafted request to the Chronocollector service.
3.  The Chronocollector service processes the malicious request without proper authorization checks.
4.  Due to the information disclosure vulnerability (CVE-2026-0239), the Chronocollector service exposes sensitive information.
5.  Attacker receives the sensitive information from the Chronocollector service in the response.
6.  Attacker analyzes the disclosed information to identify valuable data.
7.  Attacker may use the disclosed information to further compromise the system or network.

## Impact

Successful exploitation of CVE-2026-0239 allows an unauthenticated attacker to retrieve sensitive information from the Chronosphere Chronocollector service. The number of victims is dependent on the number of Chronosphere Chronocollector instances running vulnerable versions. The sectors targeted depend on the organization's using the affected Chronosphere Chronocollector. This could lead to further compromise of the system or network.

## Recommendation

*   Upgrade Chronosphere Chronocollector to version v0.116.0 or later to remediate CVE-2026-0239 (see Solution section).
*   Deploy the Sigma rule to detect suspicious network activity indicative of information disclosure attempts against the Chronosphere Chronocollector service.
