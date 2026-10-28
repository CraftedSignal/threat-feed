---
brief_id: brief-2026-10-28-intelbras-dos
event_id: brief-2026-10-28-intelbras-dos
revision: 1
activity_at: "2026-10-28T11:38:28Z"
title: Intelbras IP Camera Denial-of-Service Vulnerability
slug: 2026-10-intelbras-dos
description: An unauthenticated denial-of-service vulnerability in Intelbras IP cameras allows local network attackers to trigger infinite reboots via the firmware upgrade endpoint.
date: "2026-10-28T11:38:28Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified information
tags:
  - denial-of-service
  - iot
  - network
vendors:
  - Intelbras
products:
  - iM3B-C
  - iMX C
  - iM4 C
  - iM5 SC
  - iME 360 C
  - iM7+ FC
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.004
    subtechnique_name: Application or System Exploitation
    evidence: A single request disrupts the camera for only about a minute, but sending periodic requests keeps the device offline indefinitely.
    confidence_band: high
references:
  - https://securelist.com/intelbras-camera-vulnerability/121131/
  - https://api-cronos.intelbras.com.br/download/MIBO-CAM-SD/CAMERASIM/prod/CAMERASIM-2.800.260804-2bff9ef9d4fddd76f271ff846a5c7dad.260804.zip
  - https://backend.intelbras.com/sites/default/files/2026-10/Atualizacao_firmware_Cameras_im_C_cartao_sd.pdf
rules:
  - title: Detect Potential Unauthorized Firmware Upgrade Attempt
    description: Detects HTTP requests to the firmware upgrade endpoint on Intelbras cameras which is indicative of potential DoS exploitation.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all vulnerable Intelbras cameras to firmware R.260804
      owner: IT Operations
      due: 72h
      evidence: Intelbras patched the vulnerability and released updated firmware (R.260804)
  mitigation_plan:
    - priority: immediate
      action: Segment cameras onto a restricted VLAN to prevent local network access by unauthorized devices
      owner: IT Operations
      addresses: T1499.004
      evidence: The flaw resides in a firmware update endpoint that is accessible without authentication and allows anyone with access to the local Wi-Fi network to knock cameras offline
---

Researchers discovered a denial-of-service vulnerability affecting several Intelbras IP camera models. The vulnerability exists in the firmware upgrade service endpoint, which lacks authentication and input validation. An attacker with access to the local Wi-Fi network can send requests to this endpoint to force the camera into a reboot cycle. Periodic requests can keep the affected device offline indefinitely. Intelbras has released a firmware update (R.260804) to remediate the vulnerability. MITRE has assigned the candidate ID CAN-2026-2035970 to this issue.

## Attack Chain

1. Attacker gains access to the local Wi-Fi network where the target camera is connected.
2. Attacker identifies the camera IP address on the local network.
3. Attacker targets the unauthenticated endpoint '/firmwareUpgrade_service/Demo'.
4. Attacker sends a specially crafted request to the firmware upgrade service.
5. The camera initiates a firmware upgrade process without validating the request or firmware integrity.
6. The camera enters a reboot state, causing it to lose connection to the user and the mobile application.
7. Attacker repeats the request periodically to prevent the camera from staying online, resulting in indefinite denial of service.

## Impact

The vulnerability allows any unauthorized user on the local Wi-Fi network to perform a denial-of-service attack, rendering the security camera offline and ineffective.

## Recommendation

1. Update all affected Intelbras cameras to the latest firmware version (R.260804) immediately.
2. Isolate security cameras on a dedicated, non-broadcast VLAN to prevent unauthorized local network access.
3. Implement network-level monitoring to detect unusual traffic directed at device management ports.
