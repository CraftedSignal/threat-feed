---
brief_id: brief-2026-10-osdp-overflow
event_id: brief-2026-10-osdp-overflow
revision: 3
activity_at: "2026-10-23T22:05:51Z"
revision_history:
  - revision: 2
    at: "2026-10-21T19:59:57Z"
    checksum: sha256:1f9b7f01d26a8ec0547cc869aa258e11ced3924b6415e2afba6f0329bb43639a
    summary: added coverage for Zephyr RTOS
    changed_fields:
      - cves
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19676
  - revision: 3
    at: "2026-10-23T22:05:51Z"
    checksum: sha256:787f96f5fdc3675d579e590d8423a7c6d82a39b3c6d70444421a8747fd3321f8
    summary: added coverage for Zephyr RTOS
    changed_fields:
      - action_plan
      - cves
      - exploitation_evidence
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19741
title: Stack-Based Buffer Overflow in Zephyr RTOS OSDP Implementation
slug: 2026-10-osdp-overflow
description: A vulnerability in the Zephyr RTOS OSDP Control Panel implementation allows attackers with access to the RS-485 bus to trigger a stack-based buffer overflow and potential code execution.
date: "2026-10-19T22:24:23Z"
lastmod: "2026-10-23T22:04:39Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified technical details; fix confirmed via vendor-provided patch description.
cpes:
  - cpe:2.3:o:zephyrproject:zephyr:*:*:*:*:*:*:*:*
tags:
  - zephyr
  - rtos
  - buffer-overflow
  - osdp
  - privilege-escalation
  - kernel-vulnerability
  - zephyr-rtos
  - iot
  - vulnerability
  - embedded-systems
vendors:
  - Zephyr Project
products:
  - Zephyr RTOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The impact ranges from a hard crash of the access-control panel to potential control-flow hijack in the context of the OSDP receive thread.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'The impact is a full user-mode-to-kernel escape: an arbitrary kernel write primitive (integrity and, through it, code execution at supervisor privilege).'
    confidence_band: high
cves:
  - id: CVE-2026-76788
    cvss: 8.8
    kev_status: unknown
  - id: CVE-2026-19741
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-19676
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76788
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19676
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19741
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
    - Product Security
    - Firmware Engineering
  immediate_actions:
    - action: Identify all devices running Zephyr RTOS with OSDP CP enabled for immediate firmware patching.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-76788 indicates potential arbitrary code execution.
    - action: Review build system configurations for all Zephyr-based IoT projects to ensure CONFIG_OPENTHREAD_JOINER_PSKD is explicitly defined and not using default values
      owner: Firmware Engineering
      due: 48h
      evidence: Firmware image built with CONFIG_OPENTHREAD_JOINER_AUTOSTART=y that never overrode the PSKd therefore shipped with a publicly known joining credential
  hunt_leads:
    - lead: Monitor Thread network commissioning logs for unexpected join requests or unauthorized commissioner activity within 802.15.4 radio environments
      data_needed:
        - Thread network joiner logs
        - Commissioner authentication events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated attacker within 802.15.4 radio range of an uncommissioned device can run any stock Thread commissioner registered with J01NME
  mitigation_plan:
    - priority: immediate
      action: Apply firmware updates provided by vendors utilizing the patched Zephyr RTOS version.
      owner: IT Operations
      addresses: CVE-2026-76788
      evidence: Source notes fix adds OSDP_EVENT_MAX_DATALEN bound to handlers.
    - priority: immediate
      action: Remove default CONFIG_OPENTHREAD_JOINER_PSKD and implement BUILD_ASSERT() checks in the Zephyr build pipeline
      owner: Firmware Engineering
      addresses: CVE-2026-19741
      evidence: The fix removes the default from CONFIG_OPENTHREAD_JOINER_PSKD and adds a BUILD_ASSERT() in modules/openthread/openthread.c
updates:
  - at: "2026-10-21T19:59:14Z"
    level: L2
    summary: added coverage for Zephyr RTOS
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19676
  - at: "2026-10-23T22:04:39Z"
    level: L2
    summary: added coverage for Zephyr RTOS
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19741
---

CVE-2026-76788 identifies a critical buffer overflow vulnerability within the Open Supervised Device Protocol (OSDP) implementation in the Zephyr RTOS, specifically within the `cp_decode_response()` function. This vulnerability stems from improper bounds checking when handling `REPLY_KEYPAD` and `REPLY_RAW` frames, which are copied into stack-allocated `osdp_event` structures. Because the code trusts length fields provided by the Peripheral Device without validating them against the `OSDP_EVENT_MAX_DATALEN` constant, an attacker can supply an oversized payload.

The vulnerability is accessible to any entity with physical access to the RS-485 wiring, such as a compromised or malicious card reader. Even if Secure Channel (SC) communication is enabled, an attacker can force a secure channel deactivation by sending a single unauthenticated frame with an invalid MAC, effectively reverting the connection to plaintext. The resulting overflow can overwrite stack-based return addresses or registers on Cortex-M or RISC-V architectures, leading to either a system crash (Denial of Service) or arbitrary code execution in the context of the OSDP receive thread.

## Attack Chain

1. Attacker gains physical access to the RS-485 wiring connecting a peripheral device to the OSDP Control Panel.
2. Attacker transmits an unauthenticated frame with an incorrect MAC to the Control Panel to trigger `sc_deactivate()` and disable secure channel protection.
3. Attacker crafts a malicious OSDP frame containing a `REPLY_KEYPAD` or `REPLY_RAW` message ID.
4. Attacker includes a payload length in the frame that exceeds the 64-byte `OSDP_EVENT_MAX_DATALEN` limit.
5. The Control Panel's `osdp_process_reply()` function processes the packet after it passes initial CRC-16 checks.
6. `cp_decode_response()` fails to validate the payload length and proceeds to `memcpy()` the oversized data into the stack-allocated `osdp_event` structure.
7. The `memcpy()` operation overflows the stack buffer, overwriting adjacent memory including saved registers and the return address.
8. The OSDP thread returns execution to an attacker-controlled address, leading to arbitrary code execution or a system crash.

## Impact

Successful exploitation of this vulnerability permits unauthorized control over access-control panels. An attacker may achieve persistent remote code execution on the device, potentially bypassing security gates, manipulating access logs, or disrupting facility security infrastructure. The vulnerability affects all systems utilizing Zephyr RTOS with the `CONFIG_OSDP` and `CONFIG_OSDP_MODE_CP` features enabled, provided they do not implement manual stack-protection mitigations.

## Recommendation

* Upgrade all affected Zephyr RTOS deployments to a version that includes the fix for CVE-2026-76788, which explicitly adds bounds checking for `REPLY_KEYPAD` and `REPLY_RAW` handlers using `OSDP_EVENT_MAX_DATALEN`.
* Restrict physical access to RS-485 bus wiring to prevent unauthorized device injection or frame manipulation.
* Enable stack protection mechanisms (e.g., stack canaries) in Zephyr RTOS configurations to detect or mitigate buffer overflow attempts.
