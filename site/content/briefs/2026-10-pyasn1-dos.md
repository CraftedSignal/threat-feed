---
brief_id: brief-2026-10-29-pyasn1-dos
event_id: brief-2026-10-29-pyasn1-dos
revision: 3
activity_at: "2026-10-31T03:22:28Z"
revision_history:
  - revision: 2
    at: "2026-10-29T23:09:11Z"
    checksum: sha256:5d28df264236ad076772fbd06d908b3ecdaa016b63c57a8bbd36688688d401f5
    summary: added CVE-2026-119195 +1
    changed_fields:
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119195
  - revision: 3
    at: "2026-10-31T03:22:28Z"
    checksum: sha256:c3b9a18d7204a185501cc853b257fdd3c83e13599c0aa05a041a0f6a2e1fbb65
    summary: poc_available
    changed_fields:
      - affected_products
      - cves
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-fm9c-5rcf-2q5p
title: 'pyasn1: Denial of service via tag ID collision (CVE-2026-119194)'
slug: 2026-10-pyasn1-dos
description: The pyasn1 library is vulnerable to a denial-of-service attack due to inefficient handling of tag ID collisions during schemaless container decoding, allowing attackers to force quadratic CPU exhaustion.
date: "2026-10-29T21:10:48Z"
lastmod: "2026-10-31T03:20:17Z"
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
  validation_status: Source verified
cpes:
  - cpe:2.3:a:pyasn1_project:pyasn1:*:*:*:*:*:python:*:*
has_poc: true
vendors:
  - pyasn1
products:
  - pyasn1 (0.3.3 - 0.6.4)
  - pyasn1 (< 0.6.5)
  - pyasn1 (<= 0.6.4)
  - pyasn1 (>= 0.3.3, < 0.6.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Repeated inputs can exhaust decoder CPU and reduce service availability.
    confidence_band: high
cves:
  - id: CVE-2026-119194
    cvss: 7.5
    epss: 0.00425
    kev_status: "false"
  - id: CVE-2026-119196
    cvss: 7.5
    epss: 0.00425
    kev_status: "false"
  - id: CVE-2026-119195
    cvss: 7.5
    epss: 0.00527
    kev_status: "false"
  - id: CVE-2026-119197
    cvss: 7.5
    epss: 0.00425
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119194
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119196
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119197
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119195
  - https://github.com/advisories/GHSA-2qm8-x737-gmw5
  - https://github.com/advisories/GHSA-9m75-vc3g-4x39
  - https://github.com/advisories/GHSA-fm9c-5rcf-2q5p
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all instances of pyasn1 to version 0.6.5 or later
      owner: IT Operations
      due: 72h
      evidence: This issue is fixed in version 0.6.5.
    - action: Upgrade pyasn1 to 0.6.5 or later in all dependencies
      owner: IT Operations
      due: 72h
      evidence: This issue is fixed in version 0.6.5.
  hunt_leads:
    - lead: Monitor application services for sustained high CPU utilization spikes originating from ASN.1 decoding routines
      technique_id: T1499
      data_needed:
        - Application performance monitoring (APM) logs
        - CPU usage metrics per process/container
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker-controlled BER, CER, or DER input contains many distinct long tag IDs whose TagSet hashes collide... producing quadratic CPU work.
    - lead: Identify applications utilizing pyasn1 for ASN.1 parsing
      technique_id: T1499
      data_needed:
        - Software Bill of Materials (SBOM)
        - Dependency manifests (requirements.txt, Pipfile.lock)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: pyasn1 is a generic ASN.1 library for Python.
  mitigation_plan:
    - priority: immediate
      action: Upgrade pyasn1 to 0.6.5
      owner: IT Operations
      addresses: CVE-2026-119194
      evidence: This issue is fixed in version 0.6.5.
updates:
  - at: "2026-10-29T21:11:00Z"
    level: L2
    summary: added coverage for pyasn1 (< 0.6.5)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119196
  - at: "2026-10-29T23:08:41Z"
    level: L2
    summary: added CVE-2026-119195 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119195
  - at: "2026-10-31T03:20:09Z"
    level: L1
    summary: new product
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-2qm8-x737-gmw5
  - at: "2026-10-31T03:20:17Z"
    level: L2
    summary: poc_available
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-fm9c-5rcf-2q5p
---

pyasn1 versions 0.3.3 through 0.6.4 contain a vulnerability in the `ConstructedPayloadDecoderBase._decodeComponentsSchemaless` method. When processing schemaless container decoding for BER, CER, or DER encoded inputs, the library incorrectly stores TagSet information in a growing set. By supplying crafted inputs containing many distinct long tag IDs that cause hash collisions, an attacker can force the library into quadratic CPU work, resulting in denial of service. This issue is resolved in pyasn1 version 0.6.5.

## Impact

The vulnerability facilitates a denial-of-service (DoS) condition on applications using the affected pyasn1 library for ASN.1 decoding. This can lead to service availability exhaustion by consuming excessive CPU resources.

## Recommendation

- Upgrade pyasn1 to version 0.6.5 or later to resolve the underlying algorithmic complexity flaw.
- Audit applications utilizing pyasn1 for processing external, untrusted ASN.1 (BER/CER/DER) data to identify potential exposure points.
- Implement request timeout and resource limits for services decoding external ASN.1 data to mitigate the impact of CPU-exhaustion attacks.
