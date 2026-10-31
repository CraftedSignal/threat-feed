---
brief_id: brief-2026-10-29-node-forge-redos
event_id: brief-2026-10-29-node-forge-redos
revision: 3
activity_at: "2026-10-31T15:21:19Z"
revision_history:
  - revision: 2
    at: "2026-10-31T03:22:28Z"
    checksum: sha256:fa37f6f3fb8bf0297cb85ce0a0aaae6688badc5605bc0ede7ad1d559508842ae
    summary: poc_available
    changed_fields:
      - claim_state
      - cves
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-7wch-p9px-956x
  - revision: 3
    at: "2026-10-31T15:21:19Z"
    checksum: sha256:00c21a8be179d2fcb4993ca0fc3c6031df968da1b685e0ca6b22b49997f6c904
    summary: added coverage for node-forge (<= 1.4.0)
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-hqq3-7jhf-c5jx
title: 'Digital Bazaar node-forge: ReDoS in pem.decode() (CVE-2026-118779)'
slug: 2026-10-node-forge-redos
description: Digital Bazaar node-forge versions prior to 1.4.1 are vulnerable to a Regular Expression Denial of Service (ReDoS) in the pem.decode() function, allowing unauthenticated attackers to cause high CPU usage via malformed PEM input.
date: "2026-10-29T20:40:45Z"
lastmod: "2026-10-31T15:18:54Z"
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
  validation_status: Checked against NVD details; node-forge version constraint verified.
cpes:
  - cpe:2.3:a:digitalbazaar:node-forge:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:digitalbazaar:forge:*:*:*:*:*:*:*:*
has_poc: true
vendors:
  - Digital Bazaar
products:
  - node-forge (< 1.4.1)
  - node-forge (<= 1.4.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker able to supply PEM input to any high-level parser could consume excessive CPU with a long malformed message and cause denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-118779
    cvss: 7.5
    epss: 0.00556
    kev_status: "false"
  - id: CVE-2026-118782
    cvss: 7.5
    epss: 0.00125
    kev_status: "false"
  - id: CVE-2026-119187
    cvss: 7.5
    epss: 0.00411
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118779
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118782
  - https://github.com/advisories/GHSA-7wch-p9px-956x
  - https://github.com/advisories/GHSA-jc66-7q78-782g
  - https://github.com/advisories/GHSA-hqq3-7jhf-c5jx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119187
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch node-forge to 1.4.1 or later in all identified applications
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 1.4.1.
    - action: Upgrade all instances of node-forge to version 1.4.1 or later across the organization.
      owner: IT Operations
      due: 48h
      evidence: Fixed in node-forge 1.4.1.
  hunt_leads:
    - lead: Identify applications utilizing node-forge versions < 1.4.1 that accept PEM input from untrusted sources
      technique_id: T1499
      data_needed:
        - Application dependency manifests (package.json, yarn.lock, etc.)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerable code exists in the pem.decode() function in lib/pem.js prior to version 1.4.1.
    - lead: Identify applications using node-forge versions below 1.4.1
      data_needed:
        - Software Bill of Materials (SBOM) or package-lock.json / yarn.lock files
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The node-forge library is vulnerable to a cryptographic implementation flaw where PKCS#12 MAC or password-based encryption iteration counts of zero or less lead to the generation of predictable keys and IVs.
    - lead: Identify Node.js applications utilizing the node-forge library that handle network socket data without explicit try/catch blocks around the processing logic.
      technique_id: T1499
      data_needed:
        - Application dependency inventory (package.json files)
        - Code audit of network handling logic
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Applications that use node-forge TLS implementation, including those created by forge.tls.createConnection(), call process() on received data.
  mitigation_plan:
    - priority: immediate
      action: Upgrade node-forge to version 1.4.1
      owner: IT Operations
      addresses: CVE-2026-118779
      evidence: This issue is fixed in version 1.4.1.
    - priority: immediate
      action: Upgrade node-forge to 1.4.1 or later
      owner: IT Operations
      addresses: CVE-2026-118782
      evidence: This issue is fixed in version 1.4.1.
    - priority: immediate
      action: Wrap calls to connection.process() in try/catch blocks and ensure connection.close() is called upon failure.
      owner: IT Operations
      addresses: CVE-2026-119187
      evidence: Wrap every call to connection.process() in try/catch, and on an exception close the connection.
updates:
  - at: "2026-10-29T20:40:53Z"
    level: L2
    summary: added coverage for node-forge (< 1.4.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-118782
  - at: "2026-10-31T03:20:18Z"
    level: L2
    summary: poc_available
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-7wch-p9px-956x
  - at: "2026-10-31T15:18:54Z"
    level: L2
    summary: added coverage for node-forge (<= 1.4.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-hqq3-7jhf-c5jx
---

The node-forge library, a native JavaScript implementation of TLS, contains a vulnerability in its `pem.decode()` function within `lib/pem.js`. The library uses polynomial-time regular expressions to process PEM input, including the search for matching END lines and the parsing of encapsulated headers. An unauthenticated attacker can supply crafted, malformed PEM input to any high-level parser relying on this function, triggering catastrophic backtracking that leads to excessive CPU consumption and denial of service. This vulnerability is identified as CVE-2026-118779.

## Impact

Successful exploitation results in high CPU utilization, potentially leading to a denial-of-service condition for applications relying on the node-forge library to process user-supplied PEM files or certificates.

## Recommendation

- Upgrade the node-forge library to version 1.4.1 or later immediately.
- Inventory applications within the environment that utilize the node-forge library for certificate or PEM parsing.
- Review input validation controls for services that ingest PEM-encoded data to ensure length and complexity constraints are enforced before processing by the library.
