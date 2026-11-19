---
brief_id: brief-2026-11-19-mareforma-bundle-verification-bypass-ghsa-hxh5-gp44-rc6p
event_id: brief-2026-11-19-mareforma-bundle-verification-bypass-ghsa-hxh5-gp44-rc6p
revision: 1
activity_at: "2026-11-19T16:38:46Z"
title: 'Mareforma: verify_bundle improper signature validation (CVE-2026-71536)'
slug: 2026-11-mareforma-bundle-verification-bypass-ghsa-hxh5-gp44-rc6p
description: The Mareforma library fails to cryptographically validate individual claim signatures as documented, allowing a compromised exporter to include forged or invalid claims while the verification function incorrectly reports success.
date: "2026-11-19T16:38:46Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: test_defined
cpes:
  - cpe:2.3:a:mareforma:mareforma:*:*:*:*:*:*:*:*
vendors:
  - Mareforma
products:
  - mareforma
product_versions:
  - product: mareforma
    range: '>= 0.3.0, < 0.3.8'
cves:
  - id: CVE-2026-71536
    epss: 0.00201
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-hxh5-gp44-rc6p
  - https://cveawg.mitre.org/api/cve/CVE-2026-71536
action_plan:
  priority: elevated
  mitigation_plan:
    - priority: immediate
      action: Upgrade mareforma to version 0.3.8 or later.
      evidence: CVE-2026-71536 fixed in version 0.3.8.
  gaps:
    - No automated Sigma rules can be generated for this vulnerability as it is a logic flaw in the library code rather than a log-observable attacker behavior.
---

## Overview
Mareforma, a local verification layer for AI-assisted research, contains a vulnerability in its `verify_bundle` logic (CVE-2026-71536). From versions 0.3.0 through 0.3.7, the function fails to verify per-claim signatures despite documentation stating that it performs this check. The `JSONLDExporter._claim_node` function does not include signature material in the exported JSON-LD predicate. As a result, the verification process only performs a self-referential digest check, ensuring the bundle is internally consistent with the exporter's key, but failing to validate the authenticity of the individual claims against their purported asserters.

## Impact
A malicious or compromised exporter can successfully pass a bundle validation even when it contains claims with missing, invalid, or forged asserter signatures. Relying parties are misled into believing that claims are cryptographically verified, undermining the security guarantees provided by the SCITT-style export mechanism.

## Recommendation
Upgrade the `mareforma` library to version 0.3.8 or later, where this issue is resolved. If an immediate upgrade is not feasible, verify the implementation of `verify_bundle` to explicitly check per-claim signatures if the application requires individual claim authenticity, or update security documentation to reflect that the tool only validates internal bundle consistency.
