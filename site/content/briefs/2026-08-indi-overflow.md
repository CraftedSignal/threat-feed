---
title: Stack Buffer Overflow in INDI indiserver
slug: 2026-08-indi-overflow
description: An unauthenticated remote attacker can crash the INDI indiserver daemon via a stack-based buffer overflow triggered by malformed XML input containing excessively long tags.
date: "2026-08-17T18:50:15Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - INDI
products:
  - indiserver (<= 2.2.4.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can send a single TCP packet on port 7624 with mismatched XML tags to trigger an unbounded sprintf() write... terminating the daemon.
    confidence_band: high
cves:
  - id: CVE-2026-71979
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71979
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit network perimeter for exposed indiserver instances listening on TCP 7624
      owner: SOC
      due: 24h
      evidence: Service listens on port 7624
  mitigation_plan:
    - priority: immediate
      action: Upgrade indiserver software to version containing commit 96bbd7f
      owner: IT Operations
      addresses: CVE-2026-71979
      evidence: NVD vulnerability fix documentation
---

INDI (Instrument Neutral Distributed Interface) indiserver through version 2.2.4.2 is vulnerable to a stack-based buffer overflow in `MsgQueue.cpp`. An unauthenticated remote attacker can trigger this condition by sending a single malformed TCP packet to the default port 7624. The vulnerability arises from an unbounded `sprintf()` operation that writes user-supplied XML tag names into a fixed 1024-byte stack buffer. When the tag name exceeds this length, the overflow corrupts the stack, leading to immediate daemon termination. This flaw was addressed in commit 96bbd7f. Given the role of `indiserver` in telescope control and observatory automation, this vulnerability poses a significant risk to the availability of astronomical instrument control systems.

## Attack Chain

1. Attacker performs reconnaissance to identify systems running `indiserver` listening on TCP port 7624.
2. Attacker initiates a TCP connection to the target `indiserver` instance.
3. Attacker crafts a custom XML payload containing a tag name field greater than 1024 bytes.
4. Attacker sends the malformed XML payload within a single TCP packet to the established socket.
5. The `indiserver` process receives the packet and passes the data to the parser in `MsgQueue.cpp`.
6. The `sprintf()` function executes, performing an unbounded copy of the tag string into the stack buffer.
7. The stack-based buffer overflow occurs, corrupting the execution stack and triggering a crash.
8. The daemon service terminates, resulting in a denial-of-service for all connected clients and controlled drivers.

## Impact

Successful exploitation results in a complete denial-of-service of the `indiserver` daemon. Because the service manages the communication interface between control software and hardware drivers, a crash terminates all active sessions, disrupts data acquisition, and halts ongoing astronomical observations. The attack requires no authentication and can be performed remotely against any exposed instance.

## Recommendation

* Update `indiserver` to a version containing the fix implemented in commit 96bbd7f.
* Restrict network access to port 7624 using host-based firewalls or network ACLs to ensure only authorized control machines can reach the service.
* Deploy network intrusion detection signatures to identify TCP packets directed at port 7624 containing unusually large XML tag identifiers.
