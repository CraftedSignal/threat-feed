---
title: Denial of Service Vulnerability in PocketMine-MP
slug: 2026-09-pocketmine-dos
description: PocketMine-MP versions prior to 4.7.2 are vulnerable to a denial-of-service attack due to improper exception handling when parsing skin geometry data.
date: "2026-09-06T12:45:39Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:pocketmine:pocketmine-mp:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - game-server
vendors:
  - PocketMine-MP
products:
  - PocketMine-MP (< 4.7.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can send login or skin packets with invalid geometry JSON to trigger an unhandled RuntimeException, causing server crash.
    confidence_band: high
cves:
  - id: CVE-2022-51009
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-51009
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all PocketMine-MP instances to version 4.7.2 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2022-51009 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade PocketMine-MP to 4.7.2
      owner: IT Operations
      addresses: CVE-2022-51009
      evidence: Official fix version provided in NVD report
---

PocketMine-MP versions prior to 4.7.2 contain a vulnerability in the handling of skin geometry data parsed via the adhocore/json-comment library. The issue arises from the application's failure to properly handle exceptions triggered during the parsing of malformed or invalid JSON input within skin geometry packets. An unauthenticated attacker can exploit this by sending specially crafted login or skin packets containing invalid JSON structure. When the application attempts to parse this data, it triggers an unhandled RuntimeException, which leads to an immediate server crash, resulting in a denial-of-service (DoS) condition. This vulnerability (CVE-2022-51009) is significant because it allows remote, unauthenticated attackers to disrupt server availability by sending malicious packets. Defenders should prioritize patching to version 4.7.2 or later to mitigate this risk.

## Impact

Successful exploitation of this vulnerability results in an immediate service crash, rendering the Minecraft server instance unavailable to legitimate players. This denial-of-service condition directly impacts availability for all hosted game instances running affected versions of PocketMine-MP, requiring manual intervention by administrators to restore service.

## Recommendation

* Patch the PocketMine-MP software to version 4.7.2 or later immediately to address CVE-2022-51009.
* Monitor game server process logs for repeated runtime exceptions or sudden termination signals that coincide with login or player skin update activity.
* Review perimeter and server-side traffic logs for spikes in malformed packets targeting the Minecraft game protocol port.
