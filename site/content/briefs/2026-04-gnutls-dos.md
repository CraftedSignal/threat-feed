---
title: GNUTLS Denial of Service via Malformed ClientHello (CVE-2026-1584)
slug: 2026-04-gnutls-dos
description: A remote, unauthenticated attacker can exploit CVE-2026-1584 in gnutls by sending a specially crafted ClientHello message with an invalid Pre-Shared Key (PSK) binder value during the TLS handshake, leading to a NULL pointer dereference and a denial-of-service condition.
date: "2026-04-09T18:16:44Z"
severities:
  - high
tags:
  - cve-2026-1584
  - denial-of-service
  - gnutls
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-1584
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1584
  - https://access.redhat.com/security/cve/CVE-2026-1584
  - https://bugzilla.redhat.com/show_bug.cgi?id=2435258
rules:
  - title: Detect Malformed TLS ClientHello with Invalid PSK Binder
    description: Detects TLS ClientHello messages with invalid PSK binder values, indicative of CVE-2026-1584 exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - zeek
  - title: Detect gnutls crash
    description: Detects a gnutls process crashing, which could be caused by a NULL pointer dereference due to CVE-2026-1584
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-1584 is a vulnerability found in the gnutls library, a widely used implementation of the TLS protocol. This vulnerability allows an unauthenticated, remote attacker to cause a denial-of-service (DoS) condition on a server utilizing a vulnerable version of gnutls. The attack involves sending a specially crafted TLS ClientHello message containing an invalid Pre-Shared Key (PSK) binder value. This malformed message triggers a NULL pointer dereference within the gnutls library, leading to…
