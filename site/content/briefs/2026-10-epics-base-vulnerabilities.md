---
brief_id: brief-2026-10-27-epics-base-vulnerabilities
event_id: brief-2026-10-27-epics-base-vulnerabilities
revision: 3
activity_at: "2026-10-28T11:51:18Z"
revision_history:
  - revision: 2
    at: "2026-10-27T20:02:31Z"
    checksum: sha256:4427a9a876d217e7abbda313a1bec3a53ba9103935ebac43219e0df1f79f135a
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/epics-base-7-0-11-critical-memory-bugs-oct-2026
  - revision: 3
    at: "2026-10-28T11:51:18Z"
    checksum: sha256:8ec2e47e396106cc03c89f7081e9308006212ee463b21fafe4fad52031ba492d
    summary: new IOCs
    changed_fields:
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/epics-base-7-0-11-critical-memory-bugs-oct-2026
title: 'EPICS Base: Remote code execution and denial of service (CVE-2026-114595, CVE-2026-114596, CVE-2026-114597, CVE-2026-114598)'
slug: 2026-10-epics-base-vulnerabilities
description: EPICS Base versions 7.0.10 and earlier contain multiple critical vulnerabilities in network request processing that could allow unauthenticated remote attackers to cause denial-of-service, disclose memory contents, or execute arbitrary code.
date: "2026-10-27T16:40:03Z"
lastmod: "2026-10-28T11:50:40Z"
type: advisory
claim_state: <nil>
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
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - critical-infrastructure
  - memory-corruption
  - integer-overflow
  - rce
  - dos
vendors:
  - The EPICS Community
products:
  - EPICS Base (<=7.0.10)
  - EPICS Base (<= 7.0.10)
cves:
  - id: CVE-2026-114595
    kev_status: unknown
  - id: CVE-2026-114596
    kev_status: unknown
  - id: CVE-2026-114597
    kev_status: unknown
  - id: CVE-2026-114598
    kev_status: unknown
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-01
  - https://www.cve.org/CVERecord?id=CVE-2026-114595
  - https://www.cve.org/CVERecord?id=CVE-2026-114596
  - https://www.cve.org/CVERecord?id=CVE-2026-114597
  - https://www.cve.org/CVERecord?id=CVE-2026-114598
  - https://pwn.watch/i/epics-base-7-0-11-critical-memory-bugs-oct-2026
  - https://github.com/epics-base/epics-base/releases/tag/R7.0.11
  - https://www.securityweek.com/long-hidden-flaws-patched-in-epics-research-facility-control-software/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all EPICS Base deployments to version 7.0.11
      owner: IT Operations
      due: 24h
      evidence: The EPICS Community has made available updates to the epics-base GitHub repositories. Affected users should update to the 7.0.11 release.
  hunt_leads:
    - lead: Monitor network traffic for malformed or oversized requests directed at EPICS control ports
      technique_id: T1190
      data_needed:
        - Network IDS/IPS alerts
        - Firewall connection logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An integer overflow in network request processing can cause memory to be allocated with an incorrect size.
  mitigation_plan:
    - priority: immediate
      action: Patch EPICS Base to 7.0.11
      owner: IT Operations
      addresses: CVE-2026-114595, CVE-2026-114596, CVE-2026-114597, CVE-2026-114598
      evidence: Affected users should update to the 7.0.11 release.
updates:
  - at: "2026-10-27T20:00:39Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/epics-base-7-0-11-critical-memory-bugs-oct-2026
  - at: "2026-10-28T11:50:40Z"
    level: L1
    summary: new IOCs
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/epics-base-7-0-11-critical-memory-bugs-oct-2026
---

Multiple vulnerabilities exist in EPICS Base release 7.0.10 and prior, primarily involving integer overflows and improper handling of length parameters during network message parsing. These flaws can lead to out-of-bounds memory access, corruption, and remote code execution (RCE). The EPICS Community has released version 7.0.11 to address these issues.

## Impact

Successful exploitation of these vulnerabilities allows for process instability, denial-of-service, sensitive information disclosure from process memory, and potential execution of arbitrary code with the privileges of the EPICS Base process.

## Recommendation

* Update all EPICS Base installations to release 7.0.11 immediately.
* Review the upstream GitHub repository pull requests (PR #934, PR #937, and pvDataCPP PR #109) for technical implementation details of the fixes.
* Restrict access to EPICS network ports to trusted management subnets to minimize the attack surface until patching is complete.
