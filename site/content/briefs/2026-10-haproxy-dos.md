---
brief_id: brief-2026-10-22-haproxy-dos
event_id: brief-2026-10-22-haproxy-dos
revision: 1
activity_at: "2026-10-22T19:54:05Z"
title: 'HAProxy: Multiple Denial of Service Vulnerabilities'
slug: 2026-10-haproxy-dos
description: Multiple vulnerabilities in HAProxy have been identified that can be exploited to cause a Denial of Service.
date: "2026-10-22T19:54:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
qa_status:
  verdict: pass
  validation_status: Verified against BSI WID portal.
tags:
  - denial-of-service
  - haproxy
  - availability
vendors:
  - HAProxy
products:
  - HAProxy
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein Angreifer kann mehrere Schwachstellen in HAProxy ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4114
---

Multiple vulnerabilities have been identified in HAProxy that can be exploited by an attacker to conduct a Denial of Service attack.
