---
brief_id: brief-2026-11-09-freeswitch-stack-overflow
event_id: brief-2026-11-09-freeswitch-stack-overflow
revision: 1
activity_at: "2026-11-09T05:17:29Z"
title: 'FreeSWITCH: Pre-authentication stack overflow in mod_rtmp (CVE-2026-116567)'
slug: 2026-11-freeswitch-stack-overflow
description: A public exploit exists for a pre-authentication stack overflow in FreeSWITCH mod_rtmp allowing remote denial-of-service, alongside a related issue (CVE-2026-116782).
date: "2026-11-09T05:17:29Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:freeswitch:freeswitch:*:*:*:*:*:*:*:*
vendors:
  - FreeSWITCH
products:
  - FreeSWITCH (< 1.11.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: OS Exhaustion Flood
    evidence: A target is only called vulnerable when the listener is observed down, not when a socket closes.
    confidence_band: high
cves:
  - id: CVE-2026-116567
    cvss: 7.5
    epss: 0.00432
    kev_status: "false"
  - id: CVE-2026-116782
    cvss: 7.5
    epss: 0.00536
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=4A92CD1F-AC6A-5145-9345-DB9FC2FAA26E
  - https://github.com/carterlasalle/CVE-2026-116567
  - https://sploitus.com/exploit?id=4A92CD1F-AC6A-5145-9345-DB9FC2FAA26E&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify and disable mod_rtmp on all public-facing or sensitive FreeSWITCH instances
      owner: IT Operations
      due: 24h
      evidence: mod_rtmp is commented out of both the default module list and modules.conf.xml
  hunt_leads:
    - lead: Detect RTMP connection attempts from external infrastructure targeting port 1935
      technique_id: T1499.001
      data_needed:
        - Firewall or Netflow logs for TCP 1935
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The exploit probes RTMP ports and opens a session to fingerprint mod_rtmp vs nginx-rtmp
  mitigation_plan:
    - priority: immediate
      action: Upgrade FreeSWITCH to 1.11.2 or later
      owner: IT Operations
      addresses: CVE-2026-116567
      evidence: target FreeSWITCH < 1.11.2
---

CVE-2026-116567 is a pre-authentication stack overflow vulnerability within the FreeSWITCH `mod_rtmp` module, specifically in the `rtmp_handle_control()` function. An attacker can send a crafted RTMP user-control message to trigger an unbounded `sprintf` loop, corrupting a 200-byte stack buffer and causing the FreeSWITCH process to crash. The exploit author also includes targeting for a second vulnerability, CVE-2026-116782, triggered by non-object AMF arguments. The module is disabled by default in standard distributions, reducing the attack surface.

## Attack Chain

1. Attacker probes TCP port 1935 on the target host.
2. Attacker initiates RTMP handshake (C0/C1) and waits for server response (S0/S1/S2).
3. Attacker sends `connect` command (AMF0) targeting `live`, `sofia`, or `default` application.
4. Attacker inspects server `fmsVer` response; if `1`, the target is identified as `mod_rtmp`.
5. Attacker negotiates `SetChunkSize 4096` to ensure the payload remains in a single chunk.
6. Attacker sends a crafted RTMP `USERCTRL 0x04` message with a payload > 70 bytes.
7. The `rtmp_handle_control()` function overflows the fixed 200-byte stack buffer, resulting in a process crash.
8. Attacker polls the service port to confirm the listener is down, achieving a denial-of-service.

## Impact

The primary impact is a crash of the FreeSWITCH process, leading to a denial-of-service. Active calls are dropped. Because the overflow writes via `%02x` formatting, the control over the execution flow is limited to ASCII hex digits, making this primarily a DoS rather than a remote code execution (RCE) vector.

## Recommendation

1. Inventory all FreeSWITCH instances and verify the status of `mod_rtmp`. Disable the module if it is not strictly required.
2. Upgrade all instances running versions older than 1.11.2 to the latest patched version.
3. Implement network-level access control lists (ACLs) to restrict access to port 1935 to trusted sources only.
4. Deploy the suggested hunt leads to detect reconnaissance and exploitation attempts against RTMP services.
