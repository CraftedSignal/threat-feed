---
brief_id: brief-2026-10-23-twisted-dos
event_id: brief-2026-10-23-twisted-dos
revision: 1
activity_at: "2026-10-23T22:05:04Z"
title: 'Twisted: Denial of service via IRC buffer exhaustion (CVE-2026-115776)'
slug: 2026-10-twisted-dos
description: The Twisted framework contains a memory exhaustion vulnerability in its IRC protocol implementation that allows unauthenticated remote attackers to crash the server process by sending unbounded data streams without line feeds.
date: "2026-10-23T22:05:04Z"
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
  validation_status: Source-verified; patch version confirmed
cpes:
  - cpe:2.3:a:twistedmatrix:twisted:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - python
  - framework
vendors:
  - Twisted Matrix Labs
products:
  - Twisted (< 26.10.0rc1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated connection can continuously grow the buffer until the shared server process runs out of memory and drops all users.
    confidence_band: high
cves:
  - id: CVE-2026-115776
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115776
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Twisted framework to version 26.10.0rc1 or later
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 26.10.0rc1.
  hunt_leads:
    - lead: Identify applications using twisted.words.service.IRCUser and monitor for memory usage spikes from individual connections
      data_needed:
        - Application process memory metrics
        - Network connection duration for IRC services
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated connection can continuously grow the buffer until the shared server process runs out of memory
  mitigation_plan:
    - priority: immediate
      action: Apply patch to 26.10.0rc1
      owner: IT Operations
      addresses: CVE-2026-115776
      evidence: This issue is fixed in version 26.10.0rc1.
---

Twisted versions prior to 26.10.0rc1 are vulnerable to a denial of service (DoS) condition in the `twisted.words.protocols.irc.IRC.dataReceived` method. The component fails to enforce maximum line lengths or clear per-connection buffers for data received without line feeds. This behavior is inherited by the `twisted.words.service.IRCUser` server subclass. Because the buffering occurs prior to authentication commands, an unauthenticated attacker can connect to an IRC service and send a continuous stream of bytes to deplete available memory, causing the server process to crash and affecting all users.

## Impact
Successful exploitation leads to memory exhaustion and total denial of service for the target IRC server process. This is a remote, unauthenticated vulnerability that does not require login credentials to execute.

## Recommendation
- Upgrade the Twisted framework to version 26.10.0rc1 or later immediately.
- If upgrading is not immediately possible, implement edge protection to rate-limit or drop unauthorized IRC connections.
- Review server resource utilization monitoring for anomalous memory growth trends in applications utilizing the `twisted.words` IRC modules.
