---
brief_id: brief-2026-10-21-emudhra-intermediate-key-compromise
event_id: brief-2026-10-21-emudhra-intermediate-key-compromise
revision: 1
activity_at: "2026-10-21T07:47:00Z"
title: 'eMudhra: Eight compromised intermediate CA keys threaten TLS trust'
slug: 2026-10-emudhra-intermediate-key-compromise
description: Eight eMudhra intermediate CA private keys were compromised. A researcher found one key had the integer value 4; Mozilla blocked the affected certificates and updated its trust store.
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
vendors:
  - eMudhra
products:
  - emSign intermediate CA certificates
references:
  - https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/
  - https://scotthelme.co.uk/eight-bits-of-trust-emudhras-ca-keys-cracked-in-milliseconds/
  - https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2
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
  mitigation_plan:
    - priority: immediate
      action: Apply current browser and trust-store updates, including affected certifi bundles
      owner: IT Operations
      addresses: emSign intermediate CA certificates
      evidence: Mozilla distributed OneCRL blocks and updated NSS; certifi removed affected emSign roots in version 2026.10.18.
---

Mozilla received a report on 17 October 2026 that private keys for eight eMudhra intermediate CA certificates had been compromised. Security researcher Scott Helme independently recovered the weak keys from the public certificates and reported that one private key was the integer **4**; others included **56** and **115**. This describes a very small key value, not a four-byte certificate. A holder of a compromised CA key could issue fraudulent HTTPS certificates. Intercepting a connection would also require an on-path position. The cited sources do not establish observed malicious use of these keys.

Mozilla blocked the affected certificates through Firefox OneCRL on 17 October and released Firefox and NSS updates for clients that may not receive that block. The certifi maintainer removed the affected emSign roots from its CA bundle in version 2026.10.18.

## Recommendation

- Check which browsers, libraries, containers, and custom trust stores still trust the affected certificate chain.
- Apply current browser and NSS updates; update affected certifi installations to 2026.10.18 or later and rebuild bundled images.
- Investigate any suspicious TLS certificate chains issued through the affected intermediates, while keeping observed exploitation separate from the confirmed key compromise.
