---
title: Unpatched Shark Vacuum Flaw Allows Region-Wide Remote Control and Data Theft
slug: 2026-07-unpatched-shark-vacuum-flaw
description: A researcher discovered an unpatched vulnerability in Shark RV2320EDUS robot vacuums that allows an attacker with physical access to extract an overly permissive AWS IoT certificate, enabling region-wide remote command execution and data theft on other Shark vacuums.
date: "2026-07-16T10:54:57Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - iot-security
  - vulnerability
  - cloud-security
  - access-control
  - remote-code-execution
vendors:
  - SharkNinja
products:
  - Shark RV2320EDUS
  - Shark AV1102ARUS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Physical Access
    evidence: The certificate comes off with a screwdriver.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The mainboard exposes UART pins, the U-Boot console asks for no password, and init=/bin/sh in the boot arguments drops you to a root shell.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: ""
    evidence: the per-device key and certificate sit in /mnt/res/vapp/certs/ as ordinary files.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1538
    technique_name: Abuse of Cloud Identity
    evidence: The policy attached to that certificate was never scoped to the device holding it. Present it to Shark's cloud broker, and the broker accepts whatever you publish, addressed to any device it serves.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: The shadow carries an Exec_Command field that the management daemon appd reads and hands to a function named execute_command, which runs anything under 1,000 bytes through popen.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: landing a reverse shell... pull a live feed off the model's onboard camera... read the map of the house, and take the Wi-Fi password in plaintext.
    confidence_band: high
references:
  - https://thehackernews.com/2026/07/unpatched-shark-vacuum-flaw-could-let.html
---

A researcher operating under the handle tokay0 has publicly disclosed a critical vulnerability affecting SharkNinja's robot vacuum cleaners, specifically the RV2320EDUS model, which has remained unpatched since being reported to the vendor in March 2026. The flaw stems from an overly permissive AWS IoT certificate embedded in the device, which, when extracted, grants an attacker the ability to execute root commands, access camera feeds, read house maps, and exfiltrate Wi-Fi passwords in plaintext from other Shark vacuums within the same AWS region. This vulnerability does not rely on memory corruption or privilege escalation on the target device, but rather on the cloud broker accepting broad publish/subscribe actions from a compromised certificate. The researcher observed over 673,000 devices emitting an Exec_Response in a 24-hour period within one AWS region, indicating a wide potential impact on customers whose devices utilize the affected command handler.

## Attack Chain

1. **Physical Access:** An attacker gains physical access to a vulnerable Shark RV2320EDUS robot vacuum.
2. **Credential Access (Device Root Shell):** The attacker disassembles the vacuum, connects to UART pins on the mainboard, bypasses the U-Boot console password, and exploits a boot argument (`init=/bin/sh`) to obtain a root shell on the device.
3. **Credential Access (Certificate Extraction):** From the root shell, the attacker extracts the per-device AWS IoT key and certificate files located at `/mnt/res/vapp/certs/`.
4. **Abuse of Cloud Identity:** Using the extracted certificate, which possesses an overly permissive AWS IoT policy (allowing publish/subscribe on `$aws/things/#`), the attacker connects to SharkNinja's cloud broker.
5. **Discovery & Targeting:** The attacker subscribes to `$aws/things/#` via the broker to observe traffic and harvest serial numbers of other Shark vacuums operating in the same AWS region.
6. **Remote Code Execution:** The attacker publishes a shadow update containing an `Exec_Command` field to the specific topic of a targeted Shark vacuum.
7. **Impact (Remote Control & Data Exfiltration):** The targeted vacuum's `appd` management daemon reads the `Exec_Command` field, which is executed via `popen`, providing the attacker with capabilities such as establishing a reverse shell, accessing live camera feeds, reading house maps, and exfiltrating plaintext Wi-Fi passwords.

## Impact

The successful exploitation of this vulnerability would allow an attacker to remotely control affected Shark robot vacuums, leading to significant privacy and security compromises. Attackers could view sensitive household information through the vacuum's camera, map out the interior of homes, and steal Wi-Fi network credentials, potentially enabling further network intrusion. While the researcher tested on his own devices, the identified scope suggests that hundreds of thousands of Shark vacuums across a single AWS region could be vulnerable. SharkNinja has not yet patched the flaw or issued an official advisory, leaving devices exposed to these risks. The only current owner-side mitigation is to disconnect the vacuum from Wi-Fi, which disables app control and smart features.

## Recommendation

* **Monitor Vendor Advisories:** Regularly check SharkNinja's official channels for an upcoming security advisory or patch regarding this vulnerability.
* **Review IoT Device Policies:** For organizations that manage IoT fleets, review AWS IoT Device Defender audit checks, specifically `IOT_POLICY_OVERLY_PERMISSIVE_CHECK`, to ensure device policies are properly scoped to `iot:Connection.Thing.ThingName` and not `aws/things/*`. This is a vendor-side fix, but awareness is crucial.
* **Isolate or Disconnect Affected Devices:** Until a vendor-supplied patch is available, end-users should consider disconnecting affected Shark vacuums, such as the Shark RV2320EDUS and AV1102ARUS, from their Wi-Fi networks to prevent remote exploitation.
