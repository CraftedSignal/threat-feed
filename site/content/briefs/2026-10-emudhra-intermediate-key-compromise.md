---
brief_id: brief-2026-10-21-emudhra-intermediate-key-compromise
event_id: brief-2026-10-21-emudhra-intermediate-key-compromise
revision: 4
activity_at: "2026-10-21T13:09:06Z"
revision_history:
  - revision: 2
    at: "2026-10-21T08:26:00Z"
    checksum: sha256:ef57be40429a4874b8b5b4c1294ddf392e60eed5d5db4ab10932b38f4a9c2c99
    summary: Named the eight compromised TLS and code-signing intermediate CAs from Mozilla's incident record.
    changed_fields:
      - references
      - body
    source_urls:
      - https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
  - revision: 3
    at: "2026-10-21T08:50:04Z"
    checksum: sha256:8ef0333e7468538b01a7c7163e5e2f8560c019f12924b7d0270f9356e13964b1
    summary: Redirected the overlapping auto-generated eMudhra brief here.
    changed_fields:
      - aliases
    maintenance: true
  - revision: 4
    at: "2026-10-21T13:09:06Z"
    checksum: sha256:bd2e9f29795ced06758942f5354831f1edbf7eb3fbe4f3ccfe958721f17780cb
    summary: Consolidated the duplicate CA-key report and downstream certifi advisory into this incident brief.
    changed_fields:
      - aliases
      - description
      - tags
      - products
      - references
      - action_plan
      - body
    source_urls:
      - https://www.securityweek.com/browsers-block-emudhra-intermediate-cas-over-recoverable-private-keys/
      - https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2
aliases:
  - /briefs/2026-10-emudhra-ca-compromise/
  - /briefs/2026-10-emudhra-ca-keys/
  - /briefs/2026-10-certifi-compromised-roots/
title: 'eMudhra: Eight compromised intermediate CA keys threaten TLS trust'
slug: 2026-10-emudhra-intermediate-key-compromise
description: Eight eMudhra intermediate CA private keys were recoverable because of weak key generation. Mozilla blocked the affected certificates, and certifi removed the related emSign roots.
date: "2026-10-21T07:47:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
qa_status:
  verdict: pass
tags:
  - certificate-authority
  - tls-interception
  - supply-chain
  - cryptography
  - python
vendors:
  - eMudhra
products:
  - emSign intermediate CA certificates
  - Intermediate Certificate Authorities
  - certifi (< 2026.10.18)
references:
  - https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/
  - https://scotthelme.co.uk/eight-bits-of-trust-emudhras-ca-keys-cracked-in-milliseconds/
  - https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2
  - https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
  - https://www.securityweek.com/browsers-block-emudhra-intermediate-cas-over-recoverable-private-keys/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify TLS clients and applications that trust the affected eMudhra certificate chain
      owner: IT Operations
      due: 24h
      evidence: Mozilla reports eight compromised intermediate keys and has blocked the affected certificates in Firefox.
    - action: Identify applications and container images using certifi versions before 2026.10.18
      owner: IT Operations
      due: 24h
      evidence: The certifi maintainer removed the related emSign roots in version 2026.10.18.
  mitigation_plan:
    - priority: immediate
      action: Apply current browser and trust-store updates, including affected certifi bundles
      owner: IT Operations
      addresses: emSign intermediate CA certificates and certifi versions before 2026.10.18
      evidence: Mozilla distributed OneCRL blocks and updated NSS; certifi removed affected emSign roots in version 2026.10.18.
---

Mozilla received a report on 17 October 2026 that private keys for eight eMudhra intermediate CA certificates had been compromised. Security researcher Scott Helme independently recovered the weak keys from the public certificates and reported that one private key was the integer **4**; others included **56** and **115**. SecurityWeek subsequently reported on the same recoverable-key incident. This describes very small key values, not short certificate files. A holder of a compromised CA key could issue fraudulent HTTPS certificates. Intercepting a connection would also require an on-path position. The cited sources do not establish observed malicious use of these keys.

## Affected intermediate CAs

Mozilla's [incident record](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) identifies six TLS issuers and two code-signing issuers. The names and CCADB identifiers are:

| Purpose | Intermediate CA | CCADB ID |
| --- | --- | --- |
| TLS | EM EV TLS CA - G3B (eMudhra BV) | A012304 |
| TLS | EM OV TLS CA - G3B (eMudhra BV) | A012308 |
| TLS | EM DV TLS CA - G3B (eMudhra BV) | A012302 |
| TLS | EM EV TLS CA - G3C (eMudhra Inc) | A012296 |
| TLS | EM OV TLS CA - G3C (eMudhra Inc) | A012300 |
| TLS | EM DV TLS CA - G3C (eMudhra Inc) | A012294 |
| Code signing | EM OV CS CA - G3B (eMudhra BV) | A012306 |
| Code signing | EM OV CS CA - G3C (eMudhra Inc) | A012298 |

Use the SHA-256 certificate fingerprints in Mozilla's incident record when matching a certificate chain; a CA name alone is not a reliable cryptographic identifier.

Mozilla blocked the affected certificates through Firefox OneCRL on 17 October and released Firefox and NSS updates for clients that may not receive that block. As downstream remediation for the same incident, the certifi maintainer removed the affected emSign roots from its CA bundle in version 2026.10.18. The certifi advisory is therefore part of this certificate-chain incident, not a separate compromise.

## Recommendation

- Check which browsers, libraries, containers, and custom trust stores still trust the affected certificate chain.
- Apply current browser and NSS updates; update affected certifi installations to 2026.10.18 or later and rebuild bundled images.
- Investigate any suspicious TLS certificate chains issued through the affected intermediates, while keeping observed exploitation separate from the confirmed key compromise.
