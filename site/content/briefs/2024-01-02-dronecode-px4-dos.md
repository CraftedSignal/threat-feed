---
title: Dronecode PX4-Autopilot tattu_can Stack Buffer Overflow (CVE-2026-32707)
slug: 2024-01-02-dronecode-px4-dos
description: A stack-based buffer overflow vulnerability exists in the `tattu_can` driver of Dronecode PX4-Autopilot versions 1.17.0-rc1 and earlier; by injecting specially crafted CAN frames, an attacker can trigger an unbounded memcpy operation, leading to a stack corruption and subsequent crash of the PX4 process, resulting in a denial of service.
date: "2026-05-08T11:12:14Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Mohammed Idrees Banyamer
cpes:
  - cpe:2.3:a:dronecode:px4_drone_autopilot:*:*:*:*:*:*:*:*
  - cpe:2.3:a:dronecode:px4_drone_autopilot:1.17.0:alpha1:*:*:*:*:*:*
  - cpe:2.3:a:dronecode:px4_drone_autopilot:1.17.0:beta1:*:*:*:*:*:*
  - cpe:2.3:a:dronecode:px4_drone_autopilot:1.17.0:rc1:*:*:*:*:*:*
tags:
  - stack buffer overflow
  - denial of service
  - CVE-2026-32707
vendors:
  - Dronecode
products:
  - PX4-Autopilot (<= 1.17.0-rc1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-32707
    cvss: 5.2
    epss: 0.00027
references:
  - https://sploitus.com/exploit?id=47C989A5-9957-5FDC-961C-83967AE1527A&utm_source=rss&utm_medium=rss
  - https://github.com/PX4/PX4-Autopilot/security/advisories/GHSA-wxwm-xmx9-hr32
  - https://github.com/PX4/PX4-Autopilot/commit/3f04b7a95ace454f228b393310c4915991b85163
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32707
rules:
  - title: Detect CVE-2026-32707 Exploitation Attempt — CAN Frame Flood
    description: Detects CVE-2026-32707 exploitation attempt — Monitors for a high volume of CAN frames originating from the same source within a short timeframe, indicating a potential flood attack against the tattu_can driver
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: Detect CVE-2026-32707 Exploitation Attempt — CAN Frame with Specific Payload
    description: Detects CVE-2026-32707 exploitation attempt — Looks for CAN frames with DLC=8 and the last byte set to 0x80, indicating the start-of-transfer frame in the exploit
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability, CVE-2026-32707, was discovered in the `tattu_can` driver of the Dronecode PX4-Autopilot flight controller firmware. This vulnerability affects versions up to and including 1.17.0-rc1. The flaw stems from an unbounded memcpy() operation within the multi-frame message assembly routine of the `Tattu12SBatteryMessage` structure. Successful exploitation allows an attacker capable of injecting CAN frames into the bus to trigger a stack corruption, causing the PX4 process to crash, leading to a denial-of-service condition. The vulnerability has been patched in PX4-Autopilot version 1.17.0-rc2.

## Attack Chain

1.  Attacker injects a CAN frame into the CAN bus with DLC=8 and the last byte of the data set to 0x80. This signals the start of a new `Tattu12SBatteryMessage`.
2.  The `tattu_can` driver receives the start-of-transfer frame.
3.  The driver allocates a 48-byte buffer on the stack (`tattu_message`). The first 5 bytes from the start frame are copied into the stack buffer.
4.  The attacker sends seven subsequent CAN frames, each with DLC=8, containing the overflow payload (7 bytes of data per frame are copied).
5.  The `tattu_can` driver processes each overflow frame, copying 7 bytes from each frame into the `tattu_message` buffer using `memcpy()`, incrementing the offset by 7 bytes after each copy.
6.  After processing the seventh overflow frame, the cumulative offset exceeds the 48-byte buffer size.
7.  The attacker sends a final overflow CAN frame, which triggers the last `memcpy()` operation, writing past the boundaries of the buffer on the stack.
8.  The stack corruption leads to a segmentation fault or hard fault, causing the PX4 process to crash and resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition on the PX4-Autopilot system. On a real flight controller, this can result in a loss of control of the drone, potentially causing it to crash. The vulnerability affects systems running PX4-Autopilot versions up to and including 1.17.0-rc1 with the `tattu_can` driver enabled.

## Recommendation

*   Update PX4-Autopilot to version 1.17.0-rc2 or later, as specified in the "Vulnerable & Fixed Versions" section of this brief.
*   Disable the `tattu_can` driver if it is not required by running `tattu_can stop` or removing it from the build, as mentioned in the "Mitigation" section.
*   Apply the patch manually, incorporating the bounds check added in commit `3f04b7a`, as detailed in the "Mitigation" section.
*   Monitor CAN bus traffic for suspicious frames with DLC=8 and a last byte of 0x80, followed by multiple overflow frames as described in the attack chain; implement rules to detect anomalous CAN traffic patterns.
