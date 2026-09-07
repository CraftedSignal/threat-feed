---
title: Denial of Service Vulnerability in PocketMine-MP
slug: 2026-09-pocketmine-dos
description: PocketMine-MP versions prior to 3.26.5 and 4.0.5 are vulnerable to a denial-of-service attack due to insufficient validation of player-submitted skin data lengths.
date: "2026-09-07T13:36:13Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:pocketmine:pocketmine_mp:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
vendors:
  - PocketMine
products:
  - PocketMine-MP (< 3.26.5)
  - PocketMine-MP (< 4.0.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can submit oversized skin data fields like skinID or geometryName to trigger exceptions during NBT data serialization, causing server crashes.
    confidence_band: high
cves:
  - id: CVE-2022-51017
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-51017
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade PocketMine-MP to version 3.26.5, 4.0.5, or later.
      owner: IT Operations
      addresses: CVE-2022-51017
      evidence: CVE-2022-51017 advisory
---

PocketMine-MP versions before 3.26.5 and 4.0.5 contain a vulnerability arising from improper input validation regarding the length of skin data fields provided by game clients during the connection process. An attacker can manipulate fields such as skinID or geometryName to exceed the 32767 byte TAG_String limit imposed by the NBT protocol used by the server. When the server attempts to process or serialize this maliciously oversized data, it triggers internal exceptions within the NBT handling logic. If not properly caught or sanitized, these exceptions result in a process crash, effectively rendering the game server unavailable to legitimate players. This vulnerability represents a significant risk to service availability for server administrators operating impacted versions.

## Impact

Successful exploitation results in a persistent denial-of-service condition for the targeted PocketMine-MP game server. This disrupts gameplay for all connected users and requires manual administrative intervention to restore service availability. Organizations hosting competitive or public-facing game environments are at the highest risk of repeated service interruptions.

## Recommendation

* Upgrade all instances of PocketMine-MP to version 3.26.5 or 4.0.5 or later to resolve the underlying input validation flaw.
* Monitor server logs for repeated application-layer crashes or stack trace exceptions involving NBT serialization modules to identify potential exploitation attempts.
* Implement rate limiting or packet size inspection at the network edge, if possible, to drop incoming game packets that exceed the expected size for skin-related data payloads.
