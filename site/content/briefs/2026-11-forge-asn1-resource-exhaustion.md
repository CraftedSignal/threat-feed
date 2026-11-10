---
brief_id: brief-2026-11-10-forge-asn1-resource-exhaustion
event_id: brief-2026-11-10-forge-asn1-resource-exhaustion
revision: 1
activity_at: "2026-11-10T16:34:57Z"
title: 'Digital Bazaar node-forge: ASN.1 resource exhaustion (CVE-2026-119191)'
slug: 2026-11-forge-asn1-resource-exhaustion
description: The node-forge library is vulnerable to a denial of service (DoS) due to inadequate recursion depth enforcement and excessive memory usage during ASN.1 BIT STRING decoding, allowing attackers to crash processes with small, crafted DER or PEM inputs.
date: "2026-11-10T16:34:57Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:digitalbazaar:forge:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:digitalbazaar:forge:*:*:*:*:*:*:*:*
vendors:
  - Digital Bazaar
products:
  - node-forge (<= 1.4.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote, unauthenticated attacker can supply a small DER or PEM structure with nested BIT STRINGs to any API that parses with asn1.fromDer() ... The result is denial of service.
    confidence_band: high
cves:
  - id: CVE-2025-66031
    cvss: 7.5
    epss: 0.00446
    kev_status: "false"
  - id: CVE-2026-119191
    cvss: 7.5
    epss: 0.00429
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-rhr8-3pm8-cq29
  - https://github.com/digitalbazaar/forge/security/advisories/GHSA-554w-wpv2-vw27
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-119191
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all applications or services utilizing node-forge for PKI or certificate parsing and prioritize for upgrade to 1.4.1.
      owner: IT Operations
      due: 48h
      evidence: Fixed in node-forge 1.4.1.
  hunt_leads:
    - lead: 'Monitor application logs and system metrics for sudden spikes in memory consumption or Node.js "FATAL ERROR: JavaScript heap out of memory" crashes coinciding with incoming DER/PEM traffic.'
      technique_id: T1499
      data_needed:
        - Application process logs
        - System memory usage metrics
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: A 20 KB certificate PEM used 1.3 GB before being rejected.
  mitigation_plan:
    - priority: immediate
      action: Upgrade node-forge to 1.4.1.
      owner: IT Operations
      addresses: CVE-2026-119191
      evidence: Fixed in node-forge 1.4.1.
---

The `asn1.fromDer()` function in `node-forge` (versions <= 1.4.0) contains two vulnerabilities that allow for denial of service (DoS) via resource exhaustion. First, recursion depth limits (intended to fix CVE-2025-66031) are not enforced when decoding nested BIT STRING contents. Second, each nested BIT STRING triggers a deep copy of decoded contents, resulting in quadratic memory growth relative to nesting depth. 

An unauthenticated attacker can supply small (e.g., 20 KB to 200 KB) crafted DER or PEM files to any application using `node-forge` for PKI, TLS, or certificate parsing (such as `pki.certificateFromPem` or `pki.publicKeyFromPem`), causing excessive CPU usage or fatal memory exhaustion that cannot be caught by the application.

## Impact

Successful exploitation results in a crash of the Node.js process. The attack does not allow for unauthorized access, data exfiltration, or remote code execution; it is strictly a denial of service impact. Observed inputs of ~25 KB have triggered fatal out-of-memory errors on Node.js processes with 512 MB heaps.

## Recommendation

- Upgrade `node-forge` to version 1.4.1 or later.
- Audit applications utilizing `node-forge` to identify entry points for certificate or PEM/DER parsing (e.g., TLS clients, PKCS loaders).
- If upgrading is not immediately possible, callers of `forge.asn1.fromDer()` can pass the option `{decodeBitStrings: false}` to mitigate the vulnerability for custom parsing logic, though this alters the resulting object structure.
