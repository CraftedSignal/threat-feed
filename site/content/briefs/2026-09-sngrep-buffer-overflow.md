---
title: Stack-based Buffer Overflow in sngrep SIP Parsing
slug: 2026-09-sngrep-buffer-overflow
description: sngrep versions up to 1.8.4 are vulnerable to a stack-based buffer overflow in SIP header formatting routines, allowing attackers to trigger crashes or achieve remote code execution via malformed SIP packets.
date: "2026-09-12T19:21:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:sngrep:sngrep:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - sip
  - networking
vendors:
  - sngrep
products:
  - sngrep (<= 1.8.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can craft malicious SIP packets with oversized Call-ID, X-Call-ID, or other header fields to overflow stack buffers and cause crashes or execute arbitrary code during packet parsing and rendering.
    confidence_band: high
cves:
  - id: CVE-2026-90558
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90558
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade sngrep to a patched version beyond 1.8.4.
      owner: IT Operations
      addresses: CVE-2026-90558
      evidence: Source documentation identifies version 1.8.4 and earlier as vulnerable.
---

sngrep versions 1.8.4 and earlier contain a critical stack-based buffer overflow vulnerability (CVE-2026-90558) within its SIP attribute formatting routines. The vulnerability arises from inadequate boundary checks when parsing SIP headers, such as Call-ID or X-Call-ID, which are constrained to a 255-byte stack buffer. When an attacker sends a specially crafted SIP packet containing header values exceeding this limit, the application memory is corrupted during the rendering process. This flaw enables attackers to force a process crash, leading to a denial-of-service, or potentially overwrite return addresses to execute arbitrary code with the privileges of the sngrep process. Given that sngrep is frequently used in network monitoring environments to capture and analyze VoIP traffic, successful exploitation could facilitate remote code execution on sensitive network management infrastructure.

## Impact

Successful exploitation of this vulnerability allows for remote code execution or application crashes. This impacts network security and VoIP service providers utilizing sngrep for traffic analysis. If an attacker gains code execution, they could achieve persistence within the monitoring node, sniff additional traffic, or pivot into other network segments where the monitoring node is located.

## Recommendation

Prioritize the update of all sngrep installations to a version beyond 1.8.4 that includes the fix for CVE-2026-90558. Implement network-level ingress filtering to prevent unauthorized SIP traffic from reaching network monitoring infrastructure that is not intended to be exposed to external actors. 
