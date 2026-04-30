---
title: CoreDNS Transfer Plugin ACL Bypass Vulnerability
slug: 2024-01-03-coredns-acl-bypass
description: CoreDNS' transfer plugin prior to version 1.14.3 can select the wrong ACL stanza due to lexicographic comparison, leading to unauthorized zone transfers by clients intended to be denied by subzone-specific transfer policies.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-33489
  - acl-bypass
  - dns
  - zone-transfer
  - coredns
vendors:
  - CoreDNS
products:
  - CoreDNS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1583
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-h8mm-c463-wjq3
rules:
  - title: Detect AXFR Request for Potentially Vulnerable Subzone
    description: Detects AXFR requests targeting subzones where a parent zone might have a more permissive transfer ACL, potentially indicating an attempt to exploit CVE-2026-33489.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1583.001
    data_sources:
      - dns_query
      - coredns
  - title: Monitor CoreDNS Configuration Files for Transfer ACLs
    description: This rule monitors for changes in CoreDNS configuration files (Corefile) that define zone transfer ACLs, which could indicate an attempt to exploit CVE-2026-33489 by manipulating ACL rules.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in the CoreDNS transfer plugin related to Access Control List (ACL) stanza selection. When both a parent zone and a more-specific subzone are configured with transfer rules, CoreDNS versions prior to 1.14.3 may incorrectly prioritize the parent zone's rule over the subzone's due to a lexicographic string comparison instead of a proper longest-match algorithm. This can lead to a permissive parent-zone transfer rule overriding a more restrictive subzone rule, allowing unauthorized clients to perform AXFR/IXFR requests and retrieve zone contents they should not have access to. This vulnerability matters because it can expose sensitive DNS information to unauthorized parties, potentially aiding reconnaissance or enabling further attacks.

## Attack Chain

1. An attacker identifies a CoreDNS server running a version prior to 1.14.3.
2. The attacker determines that the CoreDNS server is configured with both a parent zone (e.g., example.org.) and a subzone (e.g., a.example.org.) with different transfer ACLs. The parent zone's ACL is more permissive than the subzone's.
3. The attacker crafts an AXFR or IXFR request specifically targeting the subzone (a.example.org.).
4. The CoreDNS server's transfer plugin incorrectly selects the parent zone's ACL due to the lexicographic comparison logic, which favors "example.org." over "a.example.org.".
5. The server authorizes the transfer based on the permissive parent zone ACL.
6. The CoreDNS server responds to the attacker's request, providing the full zone contents of the subzone.
7. The attacker receives the zone data, gaining access to information such as hostnames, IP addresses, and other DNS records that should have been protected by the subzone's restrictive ACL.

## Impact

Successful exploitation of this vulnerability allows unauthorized zone transfers, exposing sensitive DNS information. The impact is significant as it can lead to the disclosure of internal network structures, server names, and other critical data, potentially facilitating reconnaissance for further attacks. The severity is compounded by the non-intuitive nature of the vulnerability, making it difficult to detect and remediate without a clear understanding of the underlying issue.

## Recommendation

*   Upgrade CoreDNS to version 1.14.3 or later to address the vulnerability (CVE-2026-33489).
*   Review CoreDNS transfer configurations to ensure subzone ACLs are not inadvertently bypassed by more permissive parent zone ACLs.
