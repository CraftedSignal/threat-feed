---
brief_id: brief-2026-11-10-dlink-m60-hardcoded-creds
event_id: brief-2026-11-10-dlink-m60-hardcoded-creds
revision: 1
activity_at: "2026-11-10T02:01:10Z"
title: 'D-Link M60: Hard-coded credentials in emDaemon MQTT Broker (CVE-2026-125086)'
slug: 2026-11-dlink-m60-hardcoded-creds
description: A critical vulnerability in the emDaemon MQTT Broker component of D-Link M60 routers (version 1.12.B01) allows remote attackers to bypass authentication via hard-coded credentials.
date: "2026-11-10T02:01:10Z"
type: advisory
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
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment verification of firmware version
cpes:
  - cpe:2.3:a:dlink:m60:1.12.b01:*:*:*:*:*:*:*
tags:
  - hardware
  - iot
  - authentication-bypass
  - remote-access
vendors:
  - D-Link
products:
  - M60 (1.12.B01)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Such manipulation leads to hard-coded credentials.
    confidence_band: high
cves:
  - id: CVE-2026-125086
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125086
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and isolate all vulnerable D-Link M60 devices running version 1.12.B01
      owner: IT Operations
      due: 24h
      evidence: Vulnerability in D-Link M60 1.12.B01
  hunt_leads:
    - lead: Monitor for successful connections or administrative access to the MQTT broker port on D-Link devices
      technique_id: T1552.001
      data_needed:
        - Network firewall/IDS logs for MQTT traffic (typically TCP 1883/8883)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The attack can be executed remotely.
  mitigation_plan:
    - priority: immediate
      action: Apply firmware patch or restrict remote access to the broker
      owner: IT Operations
      addresses: CVE-2026-125086
      evidence: Remote, hard-coded credentials vulnerability
---

A critical vulnerability has been identified in D-Link M60 firmware version 1.12.B01. The issue resides within the emDaemon MQTT Broker component, specifically the system function associated with the configuration file '/etc/emDaemon/mosquitto.conf'. This flaw exposes hard-coded credentials, enabling remote, unauthenticated access to the device. The vulnerability is publicly disclosed and considered exploitable.

## Impact
Successful exploitation allows remote attackers to gain unauthorized access to the affected D-Link M60 router, potentially leading to full device compromise.

## Recommendation
- Inventory all D-Link M60 units in the environment to identify devices running firmware version 1.12.B01.
- Implement network-level segmentation to restrict access to the MQTT broker interface to trusted administrative subnets.
- Monitor for unauthorized authentication attempts or unexpected administrative access to network edge devices.
- Check for vendor-provided firmware updates that remediate CVE-2026-125086 and apply immediately upon release.
