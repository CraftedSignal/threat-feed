---
brief_id: brief-2026-11-01-pjsip-dns-oob
event_id: brief-2026-11-01-pjsip-dns-oob
revision: 1
activity_at: "2026-11-01T04:55:53Z"
title: 'Pjsip: Heap out-of-bounds read in DNS parser (CVE-2026-32945)'
slug: 2026-11-pjsip-dns-oob
description: A heap-based out-of-bounds read vulnerability in the Pjsip DNS parser allows unauthenticated remote attackers to cause a denial-of-service via a crafted DNS response.
date: "2026-11-01T04:55:53Z"
type: advisory
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
  validation_status: Verified against CVE-2026-32945 disclosure
cpes:
  - cpe:2.3:a:pjsip:pjproject:*:*:*:*:*:*:*:*
  - cpe:2.3:a:pjsip:pjsip:*:*:*:*:*:*:*:*
vendors:
  - Pjsip
products:
  - pjproject (<= 2.16)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An attacker can trigger a crash (Denial of Service) in applications utilizing the library, such as Asterisk or FreeSWITCH, by providing a malformed, specially crafted 20-byte DNS response.
    confidence_band: high
cves:
  - id: CVE-2026-32945
    cvss: 9.8
    epss: 0.0032
    kev_status: "false"
references:
  - https://github.com/pjsip/pjproject/security/advisories/GHSA-jr2p-p2w4-rr9q
  - https://github.com/pjsip/pjproject/commit/5311aee398ae9d623829a6bad7b679a193c9e199
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOHANNESLKS-CVE-2026-32945
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOHANNESLKS-CVE-2026-32945&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Patch pjproject to version 2.17 on all telecommunications infrastructure and VOIP gateways.
      owner: IT Operations
      due: 48h
      evidence: Fixed in pjproject 2.17 (commit 5311aee).
  hunt_leads:
    - lead: Identify applications using vulnerable Pjsip versions (<2.17) in the environment.
      technique_id: T1498
      data_needed:
        - Software inventory reports
        - Dependency analysis of VOIP applications (Asterisk, FreeSWITCH)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Affected Pjsip versions <= 2.16.
  mitigation_plan:
    - priority: immediate
      action: Restrict DNS resolution traffic to trusted, hardened upstream resolvers.
      owner: Network Security
      addresses: CVE-2026-32945
      evidence: Attack requires a network-controlled DNS server to inject malicious responses.
---

CVE-2026-32945 is a heap-based out-of-bounds (OOB) read vulnerability affecting Pjsip (pjproject) versions 2.16 and earlier. The flaw resides in the DNS compression pointer parsing logic within `get_name_len()` and `get_name()` in `dns.c`. An attacker can trigger a crash in any application utilizing this library (including Asterisk and FreeSWITCH) by responding to a DNS query with a crafted 20-byte packet where the compression pointer marker (0xC0) is the final byte, causing an out-of-bounds memory read.

## Impact
The vulnerability results in a remote denial-of-service (DoS) condition, crashing the Pjsip-based application. No remote code execution has been documented, but public proof-of-concept code is available to trigger the crash.

## Recommendation
- Upgrade all deployments utilizing the Pjsip library to version 2.17 or later immediately.
- Patching requires an update to the core library; ensure applications linked against `libpjproject` are recompiled or updated with the fixed library version (commit 5311aee).
- Review network configurations for VOIP infrastructure; ensure DNS resolution is restricted to trusted, internal, or hardened recursive resolvers to mitigate the risk of rogue DNS response delivery.
