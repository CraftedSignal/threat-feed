---
brief_id: brief-2026-11-08-openam-auth-bypass
event_id: brief-2026-11-08-openam-auth-bypass
revision: 2
activity_at: "2026-11-08T03:15:26Z"
revision_history:
  - revision: 2
    at: "2026-11-08T03:15:26Z"
    checksum: sha256:1a0fd45a342fc0e7d1f6a335aa151b729a4f3b413df5142e304d3adc109b8597
    summary: new vendor
    changed_fields:
      - affected_vendors
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/openam-16-1-4-saml-session-token-admin-takeover-cves-nov-2026
title: 'OpenAM: Authentication bypass in SAML v2.0 service provider (CVE-2026-123550)'
slug: 2026-11-openam-auth-bypass
description: OpenAM before 16.1.4 contains an authentication bypass vulnerability in its SAML v2.0 service provider that accepts unsigned assertions on the ECP (PAOS) and HTTP-Artifact bindings when WantAssertionsSigned is false.
date: "2026-11-08T02:55:27Z"
lastmod: "2026-11-08T03:14:55Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
vendors:
  - Open Identity Platform
cves:
  - id: CVE-2026-123550
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-123551
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123550
  - https://pwn.watch/i/openam-16-1-4-saml-session-token-admin-takeover-cves-nov-2026
  - https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-5c3q-hp86-xjr8
  - https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-3j2f-qhrc-rjfj
  - https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-jv8f-m88g-h6mm
  - https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-hvfc-4v4r-8p9w
  - https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-x7wr-5gxg-v833
  - https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-545c-rm35-2jj2
  - https://github.com/OpenIdentityPlatform/OpenAM/security/advisories
  - https://github.com/OpenIdentityPlatform/OpenAM/releases/tag/16.1.4
  - https://www.cve.org/CVERecord?id=CVE-2026-123551
  - https://www.cve.org/CVERecord?id=CVE-2026-123550
  - https://www.vulncheck.com/advisories/openam-14.0.0-before-16.1.4-session-token-disclosure-via-notification-websocket
updates:
  - at: "2026-11-08T03:14:55Z"
    level: L1
    summary: new vendor
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/openam-16-1-4-saml-session-token-admin-takeover-cves-nov-2026
---

OpenAM before 16.1.4 contains an authentication bypass vulnerability in its SAML v2.0 service provider that accepts unsigned assertions on the ECP (PAOS) and HTTP-Artifact bindings when WantAssertionsSigned is false. Unauthenticated remote attackers can submit forged assertions to obtain sessions as any mapped user, including administrators, and hijack single sign-on to dependent applications.
