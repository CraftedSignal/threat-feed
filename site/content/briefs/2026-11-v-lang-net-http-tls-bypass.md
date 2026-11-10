---
brief_id: brief-2026-11-10-v-lang-net-http-tls-bypass
event_id: brief-2026-11-10-v-lang-net-http-tls-bypass
revision: 2
activity_at: "2026-11-10T17:01:34Z"
revision_history:
  - revision: 2
    at: "2026-11-10T17:01:34Z"
    checksum: sha256:6159b0823d0f0e9d7ed3940b1b8e8e994174f4905e79b7cc973e69d280ed593d
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-82509&utm_source=rss&utm_medium=rss
title: 'V programming language: net.http library TLS certificate validation bypass (CVE-2026-82509)'
slug: 2026-11-v-lang-net-http-tls-bypass
description: The V programming language net.http library through version 0.5.2 fails to validate TLS certificates by default, enabling on-path attackers to perform interception or modification of HTTPS traffic.
date: "2026-11-10T16:39:04Z"
lastmod: "2026-11-10T16:59:52Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; implementation details provided.
cpes:
  - cpe:2.3:a:vlang:v:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-82509&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - tls
  - encryption
  - library
vendors:
  - V Programming Language
products:
  - V programming language standard library (<= 0.5.2)
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573.002
    technique_name: Asymmetric Cryptography
    subtechnique_id: T1573.002
    subtechnique_name: Asymmetric Cryptography
    evidence: Attackers can present an expired, self-signed, wrong-hostname, or untrusted-root certificate to successfully complete the handshake via http.get, http.post, or http.fetch, enabling interception or modification of HTTPS traffic.
    confidence_band: high
cves:
  - id: CVE-2026-82509
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82509
  - https://sploitus.com/exploit?id=CVE-2026-82509&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Inventory applications using V language net.http library
      owner: IT Operations
      due: 48h
      evidence: V programming language standard library through version 0.5.2 is vulnerable.
  hunt_leads:
    - lead: Identify outgoing HTTPS connections originating from assets using V-compiled binaries and investigate for certificate validation issues.
      technique_id: T1573.002
      data_needed:
        - Egress firewall or proxy logs
        - Application-level connectivity telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can present an expired, self-signed, wrong-hostname, or untrusted-root certificate.
  mitigation_plan:
    - priority: immediate
      action: 'Upgrade V language toolchain beyond commit 4077484 and explicitly set validate: true in HTTP configurations'
      owner: IT Operations
      addresses: CVE-2026-82509
      evidence: V programming language standard library net.http through version 0.5.2 prior to commit 4077484.
updates:
  - at: "2026-11-10T16:59:52Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-82509&utm_source=rss&utm_medium=rss
---

The net.http library in the V programming language, specifically in versions up to 0.5.2, contains a TLS certificate validation bypass. The configuration parameters SSLConnectConfig.validate and FetchConfig.validate are set to false by default. Consequently, both mbedtls and OpenSSL backends complete TLS handshakes without verifying server certificates. This vulnerability allows an on-path attacker to present invalid, expired, self-signed, or untrusted-root certificates, successfully intercepting or modifying traffic from http.get, http.post, or http.fetch operations. Developers must explicitly set validate: true to secure these connections.

## Impact

Successful exploitation allows for machine-in-the-middle attacks where an attacker can intercept, view, or modify sensitive data transmitted over HTTPS. The risk is present in any application built with V versions 0.5.2 and earlier that relies on the default net.http library behavior for HTTPS requests.

## Recommendation

- Identify applications written in the V programming language that utilize the net.http library.
- Update the V language toolchain to a version containing commit 4077484 or later.
- Audit all occurrences of http.get, http.post, and http.fetch in existing codebases to ensure that validation is explicitly enabled by setting the validate parameter to true.
- Monitor network egress from services utilizing the V language for unexpected TLS certificate mismatches or unusual certificate trust chains if visibility allows.
