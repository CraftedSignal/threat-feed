---
brief_id: brief-2026-11-06-hisense-vidaa-webdriver-access
event_id: brief-2026-11-06-hisense-vidaa-webdriver-access
revision: 1
activity_at: "2026-11-06T21:28:53Z"
title: 'Hisense VIDAA Smart TV firmware: Unauthenticated WebDriver access (CVE-2026-123993)'
slug: 2026-11-hisense-vidaa-webdriver-access
description: Hisense VIDAA Smart TV firmware version V0000.01.00a.P0220 exposes an unauthenticated WebDriver server on TCP port 4444, enabling local network attackers to execute arbitrary JavaScript and perform system-level operations via the native bridge.
date: "2026-11-06T21:28:53Z"
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
  - cpe:2.3:o:hisense:vidaa_firmware:v0000.01.00a.p0220:*:*:*:*:*:*:*
vendors:
  - Hisense
products:
  - VIDAA Smart TV firmware (V0000.01.00a.P0220)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: An attacker on the same local network can interface with this service to [...] exfiltrate sensitive device telemetry and user credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: An attacker on the same local network can interface with this service to execute arbitrary JavaScript.
    confidence_band: high
cves:
  - id: CVE-2026-123993
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123993
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Identify all devices running the vulnerable firmware version V0000.01.00a.P0220 on the network
      owner: SOC
      due: 24h
      evidence: CVE-2026-123993 affects Hisense VIDAA Smart TV firmware V0000.01.00a.P0220
  hunt_leads:
    - lead: Identify active listeners on TCP port 4444 within the network environment that correspond to Hisense Smart TV device addresses
      technique_id: T1592
      data_needed:
        - Network scan or flow data showing TCP/4444 connections
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: QA build of the Google Cobalt browser engine exposes the WebDriver automation server on TCP port 4444
---

Hisense VIDAA Smart TV firmware version V0000.01.00a.P0220 contains a vulnerability stemming from the inclusion of a QA build of the Google Cobalt browser engine. This build exposes a WebDriver automation server on TCP port 4444 across all network interfaces without requiring authentication or pairing.

## Impact

An attacker on the same local network can interface with the exposed service to execute arbitrary JavaScript within the browser context. This allows for the exfiltration of sensitive localStorage data, including ad-service credentials, MAC addresses, location data, and ACR telemetry. Furthermore, the attacker can leverage the window.hisense native bridge to execute filesystem read/write operations and modify system-state.

## Recommendation

* Inventory all Hisense VIDAA Smart TV devices on the network to identify those running firmware version V0000.01.00a.P0220.
* Restrict network access to the devices, specifically blocking incoming connections to TCP port 4444 from untrusted network segments.
* Monitor network traffic for connections to port 4444 originating from unauthorized local IP addresses.
