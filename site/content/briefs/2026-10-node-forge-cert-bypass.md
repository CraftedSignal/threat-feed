---
brief_id: brief-2026-10-29-node-forge-cert-bypass
event_id: brief-2026-10-29-node-forge-cert-bypass
revision: 1
activity_at: "2026-10-29T21:10:37Z"
title: 'node-forge: Certificate validation bypass via deprecated extensions (CVE-2026-119190)'
slug: 2026-10-node-forge-cert-bypass
description: Prior to version 1.4.1, node-forge incorrectly parses deprecated certificate extensions, potentially allowing a certificate to be accepted as a CA and enabling impersonation.
date: "2026-10-29T21:10:37Z"
type: advisory
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
products:
  - node-forge (< 1.4.1)
cves:
  - id: CVE-2026-119190
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119190
---

node-forge versions prior to 1.4.1 parsed deprecated extension OIDs 2.5.29.10 and 2.5.29.13 as basicConstraints, with pki.verifyCertificateChain() prioritizing the first extension encountered. If a trusted CA issues a certificate containing these attacker-supplied extensions, the certificate may be accepted as a CA. This allows for server or client impersonation. If the CA includes a keyUsage extension without keyCertSign, the chain is rejected. This issue is addressed in version 1.4.1.
