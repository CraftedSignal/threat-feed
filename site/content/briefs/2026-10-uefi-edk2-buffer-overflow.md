---
brief_id: brief-2026-10-27-uefi-edk2-buffer-overflow
event_id: brief-2026-10-27-uefi-edk2-buffer-overflow
revision: 1
activity_at: "2026-10-27T20:59:50Z"
title: 'TianoCore EDK II: ICMP-based buffer overflow in PXE Base Code driver (CVE-2026-97631)'
slug: 2026-10-uefi-edk2-buffer-overflow
description: A critical 16-year-old memory corruption flaw (CVE-2026-97631) in the EDK II PXE-Base Code driver allows attackers on the local network to execute arbitrary code with Ring 0 privileges during the early boot sequence.
date: "2026-10-27T20:59:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:tianocore:edk_ii:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - firmware
  - edk2
  - uefi
  - pxe
vendors:
  - AMI
  - Insyde
  - Phoenix
  - Microsoft
products:
  - TianoCore EDK II (<= 2026-10-27)
  - Project Mu (<= 2026-10-27)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The IUEFI module running on the CPU then becomes corrupted... executes the malicious code on the CPU in its UEFI firmware environment.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1542
    technique_name: Pre-OS Boot
    subtechnique_id: T1542.001
    subtechnique_name: System Firmware
    evidence: The code runs in ring 0, a CPU’s most privileged execution level. Because exploits bypass attestation processes... they present a key opportunity for elevating limited privileges.
    confidence_band: high
cves:
  - id: CVE-2026-97631
    epss: 0.00432
    kev_status: "false"
references:
  - https://arstechnica.com/security/2026/10/code-execution-flaw-in-uefi-firmware-threatens-most-servers-on-planet-earth/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory server and workstation assets that have PXE boot enabled in UEFI/BIOS settings.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-97631 is a 16-year-old buffer overflow in the PXE-Base Code driver.
  hunt_leads:
    - lead: Monitor network traffic for anomalous ICMP error packets originating from unauthorized internal hosts during device boot sequences.
      technique_id: T1542.001
      data_needed:
        - Network IDS/IPS logs capturing ICMP traffic
        - Flow logs from internal subnets hosting server boot environments
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: During this process - known as the pre-execution environment boot - the driver uses a network listener to monitor for ICMP errors.
  mitigation_plan:
    - priority: immediate
      action: Disable PXE network boot on all production systems where not required for deployment.
      owner: IT Operations
      addresses: CVE-2026-97631
      evidence: It applies only to organizations with machines that boot from local networks.
    - priority: short_term
      action: Apply BIOS/UEFI firmware updates from manufacturers once released.
      owner: IT Operations
      addresses: CVE-2026-97631
      evidence: It will require deploying a BIOS/UEFI update.
---

CVE-2026-97631 is a memory-corruption vulnerability in the PXE-Base Code driver (NetworkPkg/UefiPxeBcDxe) of the open-source TianoCore EDK II reference implementation. The vulnerability stems from an incorrect bounds check in the ICMP error handling logic, where the driver fails to restrict the copy of ICMP error messages to a fixed 504-byte buffer. An attacker with local network access can send a malicious, oversized ICMP error packet during a PXE network boot sequence to overwrite adjacent memory, allowing execution of code in the UEFI environment (Ring 0). Exploitation can bypass Secure Boot and TPM attestation, as the code runs before these security mechanisms are initialized. 

## Impact

Successful exploitation enables arbitrary code execution at the UEFI firmware level (Ring 0), bypassing Secure Boot and TPM protections. While the initial payload lacks persistence, it can be used to install secondary payloads that reside in the firmware environment. Impact is limited to devices configured to boot from a network using EDK II-based firmware.

## Recommendation

- Identify systems within the environment that utilize PXE network booting for OS deployment or maintenance.
- Contact hardware vendors (OEMs) and server manufacturers to obtain and deploy BIOS/UEFI firmware updates that patch CVE-2026-97631.
- Disable network boot (PXE) functionality on systems where it is not required for daily operations to reduce the attack surface.
- Implement network segmentation to restrict access to PXE infrastructure, ensuring only authorized deployment servers can communicate with target endpoints.
