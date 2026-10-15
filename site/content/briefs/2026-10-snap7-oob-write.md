---
title: Out-of-Bounds Write Vulnerability in Snap7
slug: 2026-10-snap7-oob-write
description: Snap7 versions up to 1.4.3 contain an out-of-bounds write vulnerability in TSnap7MicroClient::opReadArea() triggered by malicious S7 peer responses, potentially leading to memory corruption or process crashes.
date: "2026-10-15T22:49:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:snap7_project:snap7:*:*:*:*:*:*:*:*
vendors:
  - Snap7
products:
  - snap7 (<= 1.4.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Snap7... contains an out-of-bounds write vulnerability in TSnap7MicroClient::opReadArea()... resulting in a memcpy operation that overwrites client buffers.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111280
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Upgrade Snap7 library to 1.4.4 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-111280 patch requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade vulnerable Snap7 libraries
      owner: IT Operations
      addresses: CVE-2026-111280
      evidence: NVD vulnerability report
---

Snap7, a popular open-source communication suite for interfacing with Siemens S7 PLCs, contains an out-of-bounds write vulnerability in the TSnap7MicroClient::opReadArea() function. This vulnerability, tracked as CVE-2026-111280, affects all versions up to and including 1.4.3. The flaw exists due to insufficient validation of the DataLength field returned by an S7 peer. A rogue or impersonated PLC can provide a specially crafted ReadVar response, forcing the library to execute a memcpy operation of up to 65535 bytes into a fixed-size caller buffer. This condition enables memory corruption or arbitrary code execution within the context of the calling SCADA, HMI, or industrial gateway process, significantly impacting industrial control system stability and integrity.

## Impact

Successful exploitation allows for memory corruption within applications consuming the Snap7 library. This can result in denial-of-service via process crashes of critical HMI or SCADA software, or potentially arbitrary code execution by overwriting adjacent memory structures. Given the library's role as a bridge between management systems and industrial hardware, exploitation risks the reliability of industrial communication channels and the availability of control operations.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:

- Update all software implementations utilizing the Snap7 library to version 1.4.4 or later immediately.
- Audit industrial networks for unauthorized or rogue PLC devices capable of spoofing S7 communication protocol responses.
- Monitor logs for unusual process crashes in software integrations (e.g., HMI/SCADA services) that interface with S7 hardware, particularly following network communication events.
