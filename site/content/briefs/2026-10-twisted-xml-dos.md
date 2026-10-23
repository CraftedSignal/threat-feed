---
brief_id: brief-2026-10-23-twisted-xml-dos
event_id: brief-2026-10-23-twisted-xml-dos
revision: 1
activity_at: "2026-10-23T21:48:41Z"
title: 'Twisted: Unauthenticated remote memory exhaustion in domish XML stream (CVE-2026-115775)'
slug: 2026-10-twisted-xml-dos
description: The Twisted XML element stream library is vulnerable to memory exhaustion, allowing unauthenticated remote attackers to trigger a denial of service by sending unbounded, unclosed XML element trees.
date: "2026-10-23T21:48:41Z"
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
cpes:
  - cpe:2.3:a:twisted:twisted:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - memory-exhaustion
  - twisted
  - xml-parsing
vendors:
  - Twisted
products:
  - Twisted (<= 26.4.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A single stream grows an in-memory element tree without bound, amplified by per-element object overhead, until the operating system kills the server.
    confidence_band: high
cves:
  - id: CVE-2026-115775
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-3476-c5c2-fr73
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115775
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all applications using Twisted for XML processing or XMPP services.
      owner: IT Operations
      due: 24h
      evidence: The affected surface is any deployment that parses untrusted XML streams with this stack, such as an XMPP server or component.
  hunt_leads:
    - lead: Monitor XMPP or custom XML services for connections that maintain a high volume of unclosed nested tags over a prolonged duration.
      technique_id: T1499
      data_needed:
        - Application-level XML stream logs
        - Process memory usage telemetry
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: A container that is never closed keeps every child beneath it... modest-bandwidth peer, or several such streams, drives the process to memory exhaustion.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Twisted to 26.10.0rc1 or later
      owner: IT Operations
      addresses: CVE-2026-115775
      evidence: 'Affected versions: confirmed against 26.4.0'
---

Twisted contains a vulnerability in `twisted.words.xish.domish` where an unauthenticated remote peer can exhaust server memory through a specifically crafted, unclosed XML element tree. The `ExpatElementStream` parser fails to implement depth or child-count limits during XML streaming. By sending a container element and continuously streaming child elements without an end tag, an attacker forces the server to materialize every element in memory, retaining the entire tree until the process reaches memory limits and is terminated. This exploitation occurs during initial protocol negotiation, such as XMPP, before any authentication takes place.

## Impact

Successful exploitation results in a remote denial of service via memory exhaustion, causing the host process to be terminated by the operating system. There is no impact on confidentiality or integrity, and no potential for remote code execution.

## Recommendation

* Upgrade the `Twisted` package to the latest version once a fix is released.
* Implement pre-authentication XML stream size and duration limits at the application or load balancer layer for all services utilizing `twisted.words.xish.domish` for untrusted input.
* Monitor application memory metrics for anomalous, sustained growth during the connection negotiation phase for XMPP services.
