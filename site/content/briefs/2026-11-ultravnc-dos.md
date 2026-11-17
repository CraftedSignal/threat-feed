---
brief_id: brief-2026-11-13-ultravnc-dos
event_id: brief-2026-11-13-ultravnc-dos
revision: 2
activity_at: "2026-11-17T21:30:08Z"
revision_history:
  - revision: 2
    at: "2026-11-17T21:30:08Z"
    checksum: sha256:093dd4aa92a4305dea4a5c2c688106ec5103d0fa672d26a7ca4a1d1b648d5f42
    summary: added CVE-2026-128321
    changed_fields:
      - affected_products
      - affected_vendors
      - content
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - summary
      - tags
      - title
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-128321
title: 'TightVNC and UltraVNC: Heap-based buffer overflow in JPEG decoding (CVE-2026-128321)'
slug: 2026-11-ultravnc-dos
description: TightVNC and UltraVNC viewers contain a heap-based buffer overflow in Tight JPEG decoding that allows a malicious VNC server to cause an out-of-bounds heap write during connection, potentially resulting in application crashes or memory-corruption impacts.
date: "2026-11-13T16:07:31Z"
lastmod: "2026-11-17T21:29:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:glavsoft:tightvnc:1.3.10:*:*:*:*:*:*:*
  - cpe:2.3:a:ultravnc:ultravnc:1.8.2.4:*:*:*:*:*:*:*
  - cpe:2.3:a:ultravnc:ultravnc:1.8.2.5:*:*:*:*:*:*:*
  - cpe:2.3:a:ultravnc:ultravnc:1.8.2.6:*:*:*:*:*:*:*
tags:
  - buffer-overflow
  - vnc
vendors:
  - Glavsoft
  - UltraVNC
products:
  - TightVNC
  - UltraVNC
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in UltraVNC ausnutzen, um einen Denial-of-Service-Angriff durchzuführen oder beliebigen Programmcode auszuführen.
    confidence_band: high
cves:
  - id: CVE-2026-128321
    cvss: 7.8
    epss: 0.00203
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4566
  - https://cveawg.mitre.org/api/cve/CVE-2026-128321
  - https://nvd.nist.gov/vuln/detail/CVE-2026-128321
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all systems running UltraVNC to assess exposure.
      owner: IT Operations
      due: 48h
      evidence: Advisory identifies vulnerability in UltraVNC.
  hunt_leads:
    - lead: Monitor firewall logs for unusual or high-frequency traffic directed at UltraVNC listening ports, typically port 5900, from unauthorized external IP addresses.
      technique_id: T1499
      data_needed:
        - Firewall logs
        - Network traffic logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is described as allowing a remote, anonymous attacker to trigger a denial of service.
updates:
  - at: "2026-11-17T21:29:17Z"
    level: L2
    summary: added CVE-2026-128321
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-128321
---

## Overview
TightVNC and UltraVNC viewers are affected by a heap-based buffer overflow vulnerability in their Tight JPEG decoding implementation. The issue is caused by a failure to validate an attacker-controlled framebuffer rectangle width against a fixed-size decoding buffer.

## Attack Chain
A malicious VNC server can trigger an out-of-bounds heap write when a user initiates a connection to the server using an affected viewer.

## Impact
Successful exploitation can result in the VNC viewer application crashing. The vulnerability may also lead to other memory-corruption impacts; however, the specific outcomes of such corruption are not detailed in the source.

## Recommendation
- Audit environments for the identified affected versions of TightVNC and UltraVNC.
- Monitor VNC connections for anomalous behavior or unexpected application termination.
- Note that currently, no remediation or fixed versions are confirmed in the primary CNA evidence; monitor vendor security advisories for updates regarding CVE-2026-128321.
