---
title: Unauthenticated Command Execution in Pulsetto Vagus Nerve Stimulator
slug: 2026-08-pulsetto-vagus-nerve-stimulator
description: The Pulsetto Vagus Nerve Stimulator firmware contains undocumented Bluetooth Low Energy commands that allow an adjacent attacker to bypass safety mechanisms and modify stimulation settings without authentication.
date: "2026-08-11T17:37:10Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - medical-device
  - iot
  - ble
  - cve-2026-18844
vendors:
  - Pulsetto
products:
  - Pulsetto Vagus Nerve Stimulator
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The firmware of the affected product accepts several undisclosed commands over its Bluetooth Low Energy (BLE) interface.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-223-02
  - https://www.cve.org/CVERecord?id=CVE-2026-18844
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Clinical Engineering
  immediate_actions:
    - action: Reach out to the vendor (info@pulsetto.tech) for remediation updates regarding CVE-2026-18844.
      owner: Clinical Engineering
      due: 72h
      evidence: Pulsetto has not responded to requests to work with CISA to mitigate this vulnerability.
  mitigation_plan:
    - priority: short_term
      action: Restrict physical access to environments where these devices are in use.
      owner: IT Operations
      addresses: CVE-2026-18844
      evidence: Minimize network exposure for all control system devices and/or systems.
---

CISA has disclosed a high-severity vulnerability, CVE-2026-18844, affecting all versions of the Pulsetto Vagus Nerve Stimulator. The vulnerability stems from hidden functionality within the device firmware, which exposes several undisclosed commands over the Bluetooth Low Energy (BLE) interface. These commands are processed by the device without requiring authentication or encryption, effectively bypassing the security controls implemented by the official companion mobile application. An adjacent attacker within Bluetooth range can issue these commands to disable internal electrical safety mechanisms or arbitrarily modify stimulation output settings, posing a significant safety risk to users. Pulsetto has not yet provided a mitigation or patch for this issue.

## Attack Chain

1. Attacker performs reconnaissance within Bluetooth range of a target Pulsetto Vagus Nerve Stimulator.
2. Attacker initiates a Bluetooth Low Energy (BLE) connection to the target device.
3. Attacker identifies the handle or characteristic associated with the device's undocumented firmware command interface.
4. Attacker crafts a custom payload containing the unauthorized command strings.
5. Attacker transmits the unauthenticated command over the BLE protocol.
6. Device firmware receives and processes the unauthorized command without authentication or encryption.
7. Attacker successfully disables electrical safety mechanisms or alters stimulation output settings to impact the device operation.

## Impact

The vulnerability directly impacts the Healthcare and Public Health sector, as the device is deployed worldwide for patient care. If exploited, an attacker could manipulate the therapeutic output of the stimulator, potentially causing physical harm by disabling safety mechanisms or delivering unintended levels of nerve stimulation. No known in-the-wild exploitation has been reported to CISA as of the publication date.

## Recommendation

Prioritized, concrete actions for security teams managing or monitoring environments containing these devices:

* Minimize physical access to areas where these medical devices are in use by patients to reduce the likelihood of an adjacent Bluetooth attack.
* Isolate affected medical devices from critical clinical networks to prevent cross-contamination if a compromised device is used as a pivot point, although this vulnerability is currently limited to adjacent BLE access.
* Contact the vendor directly at info@pulsetto.tech to request a firmware update or remediation plan for CVE-2026-18844.
* Review site-specific security policies regarding the use of personal medical electronics in controlled facility environments.
