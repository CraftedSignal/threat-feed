---
brief_id: brief-2026-10-29-node-forge-cert-bypass
event_id: brief-2026-10-29-node-forge-cert-bypass
revision: 2
activity_at: "2026-10-31T03:22:28Z"
revision_history:
  - revision: 2
    at: "2026-10-31T03:22:28Z"
    checksum: sha256:b053a0455f73f9cd6d2aa7538287353080c4717c667be4b0613ae3b2aff23f4f
    summary: poc_available
    changed_fields:
      - affected_vendors
      - claim_state
      - cpes
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-5x38-2vff-x55p
title: 'node-forge: Certificate validation bypass via deprecated extensions (CVE-2026-119190)'
slug: 2026-10-node-forge-cert-bypass
description: Prior to version 1.4.1, node-forge incorrectly parses deprecated certificate extensions, potentially allowing a certificate to be accepted as a CA and enabling impersonation.
date: "2026-10-29T21:10:37Z"
lastmod: "2026-10-31T03:20:28Z"
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
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:digital_bazaar:node_forge:*:*:*:*:*:*:*:*
has_poc: true
vendors:
  - Digital Bazaar
products:
  - node-forge (< 1.4.1)
cves:
  - id: CVE-2026-119190
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119190
  - https://github.com/advisories/GHSA-5x38-2vff-x55p
updates:
  - at: "2026-10-31T03:20:28Z"
    level: L2
    summary: poc_available
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-5x38-2vff-x55p
---

node-forge versions prior to 1.4.1 parsed deprecated extension OIDs 2.5.29.10 and 2.5.29.13 as basicConstraints, with pki.verifyCertificateChain() prioritizing the first extension encountered. If a trusted CA issues a certificate containing these attacker-supplied extensions, the certificate may be accepted as a CA. This allows for server or client impersonation. If the CA includes a keyUsage extension without keyCertSign, the chain is rejected. This issue is addressed in version 1.4.1.
