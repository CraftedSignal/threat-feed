---
title: Denial of Service in ION-DTN via Zero-Length Payload
slug: 2026-09-ion-dtn-dos
description: ION-DTN versions prior to 4.2.1-a.1 are vulnerable to a remote denial-of-service attack, allowing unauthenticated attackers to terminate the process by sending a malformed BPv7 bundle.
date: "2026-09-10T17:07:19Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:nasa:ion-dtn:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
vendors:
  - NASA
products:
  - ION-DTN (< 4.2.1-a.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An unauthenticated remote attacker can crash the ION process by sending a BPv7 bundle with a zero-length payload.
    confidence_band: high
cves:
  - id: CVE-2026-75584
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75584
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade ION-DTN to version 4.2.1-a.1 or later to fix CVE-2026-75584
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies version 4.2.1-a.1 as the fix
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the ION-DTN port to known peer IP addresses
      owner: Network Security
      addresses: CVE-2026-75584
      evidence: Vulnerability allows unauthenticated remote exploitation
---

ION-DTN versions prior to 4.2.1-a.1 contain a denial-of-service vulnerability triggered by improper input validation within the Bundle Protocol version 7 (BPv7) stack. An unauthenticated remote attacker can exploit this flaw by sending a specially crafted BPv7 bundle containing a zero-length payload. The vulnerability resides in the canonicalizePayloadBlock() function located in bpsec_util.c, which passes the payload length to the zco_clone() function without verification. This lack of validation triggers a failed CHKZERO assertion, resulting in a call to sm_Abort() and the immediate termination of the ION process via a SIGABRT signal. Because the crash occurs before HMAC verification is performed, no valid credentials or keys are required to successfully trigger the service interruption, making the system highly susceptible to remote disruption.

## Attack Chain

1. Attacker identifies a network-exposed instance running an affected version of ION-DTN (< 4.2.1-a.1).
2. Attacker prepares a malicious BPv7 bundle packet with a payload length field explicitly set to zero.
3. Attacker transmits the malformed bundle over the network to the target ION-DTN service endpoint.
4. The target system receives the packet and initiates processing within the Bundle Protocol (BP) stack.
5. The canonicalizePayloadBlock() function processes the bundle and invokes zco_clone() with the unchecked zero-length value.
6. The zco_clone() function triggers a CHKZERO assertion failure due to the invalid length.
7. The process calls sm_Abort() and terminates abruptly via SIGABRT, resulting in a denial of service.

## Impact

Successful exploitation results in the immediate, unauthenticated termination of the ION-DTN process. This impact is significant for mission-critical deployments using Delay-Tolerant Networking (DTN) protocols where uptime is essential for data relay operations. If exploited, the service remains offline until manual intervention restarts the process, potentially leading to critical data loss or communication outages across affected network nodes.

## Recommendation

Prioritized actions for administrators of ION-DTN systems:
- Upgrade all instances of ION-DTN to version 4.2.1-a.1 or later to remediate the vulnerability identified in CVE-2026-75584.
- Implement network-level filtering to restrict access to ION-DTN services to known and trusted peer nodes to mitigate the impact of unauthenticated access.
- Deploy monitoring systems to detect and alert on abnormal process termination events (e.g., SIGABRT) or unexpected service restarts in the ION environment.
