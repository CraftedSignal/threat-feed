---
title: CODESYS Modbus Vulnerability Enables Denial of Service
slug: 2026-05-codesys-modbus-dos
description: A remote, anonymous attacker can exploit a vulnerability in CODESYS Modbus to perform a denial of service attack.
date: "2026-05-12T10:08:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - modbus
  - codesys
vendors:
  - CODESYS
products:
  - CODESYS Modbus
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1464
rules:
  - title: Detect Suspicious Modbus Traffic
    description: Detects Modbus traffic that deviates from normal patterns, potentially indicating an attack.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
  - title: Detect CODESYS Modbus DoS Attempt
    description: Detects a potential denial-of-service attempt against CODESYS Modbus by monitoring for excessive Modbus requests from a single source.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A vulnerability in CODESYS Modbus allows an unauthenticated, remote attacker to cause a denial-of-service condition. The specific nature of the vulnerability is not detailed, but it resides within the CODESYS Modbus component. This means that systems using CODESYS Modbus for industrial control or automation are potentially vulnerable. While the advisory lacks specific details, the potential disruption to industrial processes due to a denial-of-service warrants attention from security teams.

## Attack Chain

1. The attacker identifies a target system running CODESYS Modbus.
2. The attacker sends a specially crafted Modbus request to the target system.
3. The CODESYS Modbus component receives and processes the malicious request.
4. Due to the vulnerability, the CODESYS Modbus component enters a fault state.
5. The fault state consumes excessive system resources (CPU, memory).
6. The system becomes unresponsive or crashes.
7. Industrial processes controlled by the affected system are disrupted.
8. The denial-of-service condition persists until the system is manually restarted or patched.

## Impact

Successful exploitation of this vulnerability can lead to a denial of service, disrupting industrial processes and potentially causing financial losses. While the exact number of affected systems is unknown, any organization using CODESYS Modbus is potentially at risk. The impact includes loss of control over industrial equipment, production downtime, and potential safety hazards.

## Recommendation

*   Apply the latest patches and updates for CODESYS Modbus as soon as they become available from the vendor.
*   Monitor network traffic for suspicious Modbus requests (see rule "Detect Suspicious Modbus Traffic").
*   Implement network segmentation to limit the impact of a potential denial-of-service attack.
*   Review and harden the configuration of CODESYS Modbus installations according to vendor best practices.
*   Enable logging for Modbus traffic and monitor logs for anomalies (see rule "Detect CODESYS Modbus DoS Attempt").
