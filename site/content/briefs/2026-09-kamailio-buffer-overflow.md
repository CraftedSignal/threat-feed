---
title: Remote Heap-Based Buffer Overflow in Kamailio CDP Diameter Receiver
slug: 2026-09-kamailio-buffer-overflow
description: A heap-based buffer overflow vulnerability in the Kamailio CDP Diameter Receiver module (CVE-2026-93962) allows unauthenticated remote attackers to achieve potential code execution or denial of service.
date: "2026-09-20T06:18:06Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:kamailio:kamailio:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network
vendors:
  - Kamailio
products:
  - Kamailio (5.8.8, 6.0.7, 6.1.4, 6.2.0-dev1 and earlier)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-93962
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93962
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Kamailio to patched versions (6.0.8 or equivalent)
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 6.0.8 is sufficient to resolve this issue.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Diameter ports
      owner: Network Security
      addresses: CVE-2026-93962
      evidence: It is possible to launch the attack remotely.
---

Kamailio is vulnerable to a heap-based buffer overflow within the CDP Diameter Receiver component, specifically impacting the shm_malloc function located in 'src/modules/cdp/receiver.c'. This vulnerability, identified as CVE-2026-93962, affects Kamailio versions up to 5.8.8, 6.0.7, 6.1.4, and 6.2.0-dev1. An unauthenticated remote attacker can exploit this flaw by sending specially crafted Diameter protocol messages to the receiver, leading to heap memory corruption. Publicly available exploit code has been reported, increasing the risk of active exploitation. Defenders should prioritize patching, as the vulnerability resides in core signaling handling components often exposed to network traffic. Successful exploitation could result in service instability or remote code execution, depending on the memory layout and attacker control over the overflowed data.

## Impact

The vulnerability poses a high risk to telecommunications and VoIP infrastructure relying on Kamailio for Diameter signaling. A successful exploit can lead to unauthorized code execution, allowing for lateral movement within the network, or persistent denial of service by crashing the process. Given the public availability of exploit code, any internet-facing or unsegmented Kamailio instance is at immediate risk of compromise.

## Recommendation

- Upgrade Kamailio to version 6.0.8 or the latest stable releases (>= 5.8.9, >= 6.0.8, >= 6.1.5, >= 6.2.0-dev2) which contain the official patches for CVE-2026-93962.
- Apply the vendor-provided patch (38711a3e788de0130d48cb485578c482b57d9351) if a full version upgrade is not immediately feasible.
- Implement strict network segmentation and access control lists (ACLs) to limit access to the Diameter signaling port (typically 3868) to only known, authorized peers.
- Monitor Kamailio process logs for frequent unexpected restarts or segment faults (SIGSEGV), which may indicate exploitation attempts or service crashes.
