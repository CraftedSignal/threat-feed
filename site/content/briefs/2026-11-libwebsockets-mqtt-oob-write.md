---
brief_id: brief-2026-11-05-libwebsockets-mqtt-oob-write
event_id: brief-2026-11-05-libwebsockets-mqtt-oob-write
revision: 1
activity_at: "2026-11-05T07:41:25Z"
title: 'libwebsockets: MQTT client out-of-bounds write (CVE-2026-114550)'
slug: 2026-11-libwebsockets-mqtt-oob-write
description: An unauthenticated out-of-bounds write vulnerability in the libwebsockets MQTT client allows a malicious broker to hijack control-flow via crafted PUBACK packets (CVE-2026-114550).
date: "2026-11-05T07:41:25Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
cpes:
  - cpe:2.3:a:libwebsockets:libwebsockets:*:*:*:*:*:*:*:*
tags:
  - mqtt
  - libwebsockets
  - memory-corruption
  - rce
vendors:
  - libwebsockets
products:
  - libwebsockets (v4.2 - v4.5.8)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An unauthenticated out-of-bounds write in libwebsockets MQTT client enables control-flow hijack.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attacker runs the broker... MQTT client role builds only... the attack surface is the client.
    confidence_band: high
cves:
  - id: CVE-2026-114550
    cvss: 8.1
    epss: 0.00842
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=E7719719-415B-5A92-85ED-D18C97271A63
  - https://github.com/warmcat/libwebsockets/commit/c9e8e1834d7f13038c82963086b90e2ee9c5b44c
  - https://sploitus.com/exploit?id=E7719719-415B-5A92-85ED-D18C97271A63&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch libwebsockets to version 5.0.0 or apply commit c9e8e1834.
      owner: IT Operations
      due: 72h
      evidence: Upstream fix commit c9e8e1834d7f13038c82963086b90e2ee9c5b44c.
  hunt_leads:
    - lead: Monitor client-side MQTT traffic for malformed PUBACK packets or signs of connection instability following PUBACK reception.
      technique_id: T1190
      data_needed:
        - MQTT application logs
        - Network traffic headers (MQTT/TCP)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The broker learns the victim's QoS1 publish packet-id from the wire so the crafted PUBACK completes cleanly.
  mitigation_plan:
    - priority: immediate
      action: Upgrade libwebsockets to v5.0.0 or later.
      owner: IT Operations
      addresses: CVE-2026-114550
      evidence: Upstream fix commit.
---

CVE-2026-114550 is an unauthenticated out-of-bounds write vulnerability in the libwebsockets (lws) MQTT client role. The issue occurs when the `_lws_mqtt_rx_parser` function incorrectly handles the properties-length variable byte integer (VBI) within a PUBACK packet. If the parser is steered into an improper state, it fails to reset the `fixed_seen` counter, allowing an attacker to perform a sequential OOB write of attacker-controlled bytes into the heap. This corruption can target `lws_sorted_usec_list_t` timers and function-pointer tables, facilitating control-flow hijacking.

## Attack Chain

1. The client establishes a connection to a malicious, attacker-controlled MQTT broker.
2. The attacker sends a specially crafted PUBACK packet to the client.
3. The parser processes the PUBACK properties length, enters an incorrect state (`LMQCPP_PUBACK_VH_PKT_ID`), and fails to reset the `fixed_seen` counter.
4. The parser consumes subsequent bytes from the malicious packet as if they were packet headers, writing them sequentially into the `_lws_mqtt_related` heap allocation.
5. The OOB write overwrites internal parser bookkeeping, timer structures, and function pointers.
6. The parser sustains the write process indefinitely by steering its own internal state and bounds-check variables via the controlled data.
7. The client triggers the corrupted pointer (e.g., a timer callback or `qos2_state_ops`), resulting in a controlled jump to attacker-supplied memory.

## Impact

The vulnerability allows an attacker to achieve control-flow hijacking, potentially leading to remote code execution (RCE). Practical exploitation requires bypassing ASLR via heap grooming and knowledge of exact build offsets, but the availability of a functional proof-of-concept (PoC) increases the risk of exploitation for unpatched systems.

## Recommendation

* Update libwebsockets to version 5.0.0 or later, or ensure the library is patched with commit `c9e8e1834d7f13038c82963086b90e2ee9c5b44c`.
* Inventory all systems, IoT devices, or services utilizing libwebsockets with MQTT support enabled (`-DLWS_ROLE_MQTT=1`).
* Restrict client connectivity to known, trusted MQTT brokers to prevent exploitation by malicious brokers.
