---
title: BlueZ Stack-Based Buffer Overflow in Bluetooth Discovery
slug: 2026-08-bluez-buffer-overflow
description: A stack-based buffer overflow in the BlueZ Linux Bluetooth stack allows an adjacent attacker to trigger a denial-of-service or potential code execution via a malformed Extended Inquiry Response packet.
date: "2026-08-25T22:49:47Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - Red Hat
products:
  - Red Hat Enterprise Linux 10
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 8
  - Red Hat Enterprise Linux 9
  - BlueZ
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A remote user within Bluetooth radio range can send a specially crafted Extended Inquiry Response (EIR) packet that causes a buffer overflow... may allow for arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-80186
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80186
  - https://access.redhat.com/security/cve/CVE-2026-80186
  - https://github.com/bluez/bluez/security/advisories/GHSA-68h6-5qgp-3975
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch the bluez package across all RHEL environments.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-80186 vendor advisory
  mitigation_plan:
    - priority: immediate
      action: Disable bluetoothd service on non-essential systems.
      owner: IT Operations
      addresses: CVE-2026-80186
      evidence: Source supports disabling services as effective mitigation.
---

CVE-2026-80186 identifies a stack-based buffer overflow vulnerability within the BlueZ Bluetooth protocol stack, which serves as the official Linux Bluetooth subsystem. This flaw originates from improper size validation when processing Extended Inquiry Response (EIR) packets during the Bluetooth discovery phase. A remote, unauthenticated attacker positioned within Bluetooth radio range can transmit a specially crafted EIR packet to a target device. 

When the victim device's `bluetoothd` service processes this malformed packet during an inquiry procedure, the overflow occurs. This may result in the immediate crashing of the `bluetoothd` daemon, leading to a denial-of-service, or potentially enabling arbitrary code execution with the privileges of the service. Given that Bluetooth discovery is often active on mobile and IoT-based Linux systems, this vulnerability poses a significant risk to localized environments. The vulnerability has been confirmed in Red Hat Enterprise Linux versions 7, 8, 9, and 10.

## Attack Chain

1. Attacker identifies a target Linux device with an active Bluetooth radio.
2. Attacker initiates a scan or waits for the target to enter a discoverable state.
3. Attacker crafts a malicious Extended Inquiry Response (EIR) packet exceeding expected buffer lengths.
4. Attacker broadcasts the malicious EIR packet while the target `bluetoothd` service is performing discovery.
5. The `bluetoothd` process receives the malformed packet via the HCI (Host Controller Interface) socket.
6. Lack of boundary checking in the BlueZ stack causes the stack-based buffer overflow during packet parsing.
7. The `bluetoothd` service crashes or execution flow is redirected to malicious payload.

## Impact

Successful exploitation results in the disruption of Bluetooth services due to the crash of the `bluetoothd` daemon. In scenarios where the overflow leads to code execution, an attacker gains the ability to execute commands on the host OS with the privileges of the Bluetooth process, potentially leading to unauthorized data access or system compromise within radio range.

## Recommendation

- Apply the latest security patches for the `bluez` package provided by your Linux distribution vendor to address CVE-2026-80186.
- Disable Bluetooth services on servers and systems where Bluetooth connectivity is not required to eliminate the attack surface.
- Implement network-level ingress/egress filtering, though note this vulnerability is physically bound to radio range.
- Monitor logs for repeated `bluetoothd` service crashes or restarts which may indicate active exploitation attempts.
