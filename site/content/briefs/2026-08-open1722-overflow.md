---
title: Stack Buffer Overflow in COVESA Open1722
slug: 2026-08-open1722-overflow
description: COVESA Open1722 versions through 0.9.2 are vulnerable to a stack-based buffer overflow in the avtp_to_can function that allows unauthenticated remote attackers to achieve arbitrary code execution via crafted UDP datagrams.
date: "2026-08-17T18:50:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - buffer-overflow
  - automotive
  - cve-2026-73522
vendors:
  - COVESA
products:
  - Open1722 (0.9.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1212
    technique_name: Exploitation for Credential Access
    evidence: The avtp_to_can() function increments its write index without bounding it against the caller-supplied array size, and because the listener accepts datagrams from any sender matching a hardcoded unauthenticated stream ID transmitted in plaintext, attackers can corrupt adjacent stack memory to achieve arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-73522
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73522
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Restrict network access to systems running Open1722 to authorized segments only.
      owner: Network Security
      due: 24h
      evidence: Exploitation requires sending crafted UDP datagrams to the listener.
  mitigation_plan:
    - priority: immediate
      action: Patch Open1722 to a version containing the bounds check fix.
      owner: IT Operations
      addresses: CVE-2026-73522
      evidence: NVD vulnerability entry
---

COVESA Open1722 versions up to 0.9.2 contain a critical stack-based buffer overflow vulnerability in the avtp_to_can() function. The vulnerability is triggered when the software processes a crafted UDP datagram containing more than 15 ACF-CAN messages. The implementation incorrectly increments the write index for a fixed 15-slot stack array without performing bounds checking against the caller-supplied array size. 

Because the library listens for datagrams from any sender that matches a hardcoded, unauthenticated stream ID transmitted in plaintext, an attacker on the local network segment can send malicious packets to the listener. Successful exploitation allows for the corruption of adjacent stack memory, leading to a crash (denial of service) or the potential for arbitrary code execution in the context of the process running Open1722. This issue is particularly relevant to automotive networking components utilizing the IEEE 1722 protocol standard.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to crash systems using Open1722 or potentially gain execution privileges on the host. This poses a significant risk to in-vehicle networking and automotive infrastructure where IEEE 1722 implementations are deployed.

## Recommendation

- Upgrade to a patched version of the Open1722 library immediately upon availability.
- Implement network-level segmentation to restrict UDP traffic directed at the Open1722 listener to known, authorized sources only.
- Monitor network traffic for malformed IEEE 1722 (AVTP) datagrams containing an abnormally high count of ACF-CAN messages that exceed standard operational thresholds.
