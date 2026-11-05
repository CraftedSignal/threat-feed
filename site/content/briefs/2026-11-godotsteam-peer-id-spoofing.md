---
brief_id: brief-2026-11-04-godotsteam-peer-id-spoofing
event_id: brief-2026-11-04-godotsteam-peer-id-spoofing
revision: 2
activity_at: "2026-11-05T20:27:40Z"
revision_history:
  - revision: 2
    at: "2026-11-05T20:27:40Z"
    checksum: sha256:0ebf55c817c0c2daf2719acfc70067e71c58f06de890f31362a02297407d9194
    summary: added CVE-2026-123017
    changed_fields:
      - claim_state
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://seclists.org/oss-sec/2026/q4/524
title: 'GodotSteam: Server peer ID spoofing'
slug: 2026-11-godotsteam-peer-id-spoofing
description: A vulnerability in GodotSteam versions 4.17 through 4.23.2 allows any multiplayer peer to claim the server ID of 1, enabling unauthorized administrative command execution.
date: "2026-11-04T21:08:34Z"
lastmod: "2026-11-05T20:26:33Z"
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
cpes:
  - cpe:2.3:a:godotsteam:godotsteam:*:*:*:*:*:*:*:*
vendors:
  - GodotSteam
products:
  - GodotSteam (4.17 through 4.23.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: A player who writes 1 is treated as the server and can issue the commands a server issues.
    confidence_band: high
cves:
  - id: CVE-2026-123017
    cvss: 6.5
    epss: 0.00258
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/518
  - https://seclists.org/oss-sec/2026/q4/524
action_plan:
  priority: elevated
  owners:
    - SOC
    - Development
  hunt_leads:
    - lead: Identify game sessions where multiple clients claim the server peer ID (ID 1) or unexpected administrative commands are received from non-server SteamIDs.
      technique_id: T1565
      data_needed:
        - Application-level game server logs
        - Custom network packet telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A player who writes 1 is treated as the server and can issue the commands a server issues.
  mitigation_plan:
    - priority: immediate
      action: Implement secondary validation of administrative commands based on SteamID rather than peer ID.
      owner: Development
      addresses: GodotSteam peer ID spoofing
      evidence: Steam verifies the account behind each connection, but GodotSteam accepts whatever peer ID the sender writes into its first packet.
updates:
  - at: "2026-11-05T20:26:33Z"
    level: L2
    summary: added CVE-2026-123017
    sources:
      - oss-security
    source_urls:
      - https://seclists.org/oss-sec/2026/q4/524
---

GodotSteam versions 4.17 through 4.23.2 contain a vulnerability where the library fails to validate the peer ID transmitted in initial network packets against the Steam-verified account identity. In Godot, the server is identified by peer ID 1. Because the library accepts the peer ID provided by the sender without cross-referencing it with the Steam authentication layer, any connected client can spoof their ID as 1 and gain the privileges reserved for the game server.

## Impact

Successful exploitation allows a malicious client to impersonate the game server and issue administrative commands within the session.

## Recommendation

* Update GodotSteam to a patched version beyond 4.23.2 as soon as one is made available by the maintainers.
* Implement server-side validation for all critical administrative actions to ensure that commands are only accepted when they originate from the host's actual SteamID, rather than relying solely on internal peer IDs.
* Perform code audits on game logic that relies on the peer ID value provided by the GodotSteam library for authorization.
