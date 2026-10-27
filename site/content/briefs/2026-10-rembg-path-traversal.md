---
brief_id: brief-2026-10-26-rembg-path-traversal
event_id: brief-2026-10-26-rembg-path-traversal
revision: 2
activity_at: "2026-10-27T17:58:45Z"
revision_history:
  - revision: 2
    at: "2026-10-27T17:58:45Z"
    checksum: sha256:5a12a04713f201efc66e9ed2fd261a598686df7d642bc2de02d9fd1340418ca6
    summary: poc_available
    changed_fields:
      - affected_products
      - affected_vendors
      - claim_state
      - cpes
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-qr6x-7v33-6qmg
title: 'Rembg: Arbitrary file disclosure and arbitrary ONNX computation (CVE-2026-115924)'
slug: 2026-10-rembg-path-traversal
description: Unauthenticated attackers can exploit a path traversal vulnerability in the Rembg /api/remove endpoint to download malicious ONNX files, leading to arbitrary ONNX computation and file disclosure.
date: "2026-10-26T21:47:12Z"
lastmod: "2026-10-27T17:58:11Z"
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
cpes:
  - cpe:2.3:a:rembg:rembg:*:*:*:*:*:*:*:*
has_poc: true
vendors:
  - Rembg
products:
  - rembg (< 2.0.82)
cves:
  - id: CVE-2026-115924
    cvss: 8.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115924
  - https://github.com/advisories/GHSA-qr6x-7v33-6qmg
updates:
  - at: "2026-10-27T17:58:11Z"
    level: L2
    summary: poc_available
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-qr6x-7v33-6qmg
---

Rembg versions prior to 2.0.82 contain a vulnerability in the /api/remove endpoint (CVE-2026-115924). The endpoint improperly processes the `extras.sam_model` parameter, passing it through `rembg/commands/s_command.py` to `rembg/sessions/sam.py`. 

An attacker can supply a `sam_model` value combining path traversal and URL fragment syntax. This allows the attacker to force the application to download malicious ONNX encoder and decoder files into a local path. These files can then be used to load target files via ONNX external data, enabling the disclosure of file contents through the returned PNG mask and the execution of arbitrary ONNX computation.
