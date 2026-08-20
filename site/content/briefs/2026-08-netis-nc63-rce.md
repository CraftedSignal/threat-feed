---
title: Unauthenticated RCE in Netis NC63 via Stack Buffer Overflow
slug: 2026-08-netis-nc63-rce
description: An unauthenticated stack-based buffer overflow in the Netis NC63 router management interface allows remote code execution via a crafted HTTP request to skk_set.cgi.
date: "2026-08-20T00:48:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-76071
  - rce
  - network-security
  - buffer-overflow
vendors:
  - Netis
products:
  - NC63 AC1200 Wireless Dual Band Gigabit MU-MIMO Router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can send a crafted HTTP request... to overwrite the function's return address.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Successful exploitation can execute attacker-selected commands in the router-management context.
    confidence_band: high
references:
  - https://sploitus.com/exploit?id=E6239A64-7F8A-5C59-AACC-41AE38C32A88
  - https://vulners.com/cve/CVE-2026-76071
rules:
  - title: Detect CVE-2026-76071 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-76071 by identifying unusually long strings in the destHost parameter of skk_set.cgi POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate Netis NC63 management interfaces from internet exposure
      owner: IT Operations
      due: 24h
      evidence: Public exploit available for critical unauthenticated RCE
  hunt_leads:
    - lead: Search logs for POST requests to /cgi-bin/skk_set.cgi with unusually long strings
      technique_id: T1190
      data_needed:
        - Webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source details the specific vulnerable parameter and handler
  mitigation_plan:
    - priority: immediate
      action: Block access to web management interface from WAN
      owner: IT Operations
      addresses: CVE-2026-76071
      evidence: Remote unauthenticated RCE
---

Researchers identified a critical vulnerability, tracked as CVE-2026-76071, affecting the Netis NC63 AC1200 Wireless Dual Band Gigabit MU-MIMO Router running firmware version NC63_V3.0.0.3327. The vulnerability exists within the `skk_set.cgi` handler, which processes the `ipFilterList` parameter using the `sscanf` function with an unbounded `%[^,]` format specifier. 

Because the underlying code copies user-supplied input into a 16-byte local stack buffer without bounds checking, an unauthenticated attacker can supply an overly long string in the `destHost` field to overwrite the function's saved return address. The vulnerability is highly impactful as the router's CGI interface runs with root privileges and lacks modern exploit mitigations like stack canaries, NX, or RELRO. Proof-of-concept code is publicly available, enabling attackers to gain full device control, redirect traffic, or extract configuration secrets from vulnerable routers exposed to the network.

## Attack Chain

1. Attacker reconnaissance identifies an internet-facing Netis NC63 router with the management CGI interface exposed.
2. The attacker crafts a malicious HTTP POST request targeting `/cgi-bin/skk_set.cgi`.
3. The request body includes the `ipFilterList=mod` trigger to invoke the vulnerable parser.
4. The attacker provides a specially crafted, long string in the `destHost` parameter to exceed the 16-byte destination buffer.
5. The `sscanf` function writes the payload into the stack frame, overflowing the buffer and overwriting the saved frame pointer and return address (ra).
6. The parser epilogue executes, causing the CPU to jump to an attacker-controlled address (e.g., the system() PLT path).
7. The attacker provides a command-string suffix in the original request to execute arbitrary system commands as root.
8. Successful execution leads to full device compromise and potential persistence or traffic manipulation.

## Impact

Successful exploitation results in arbitrary command execution with root privileges on the affected Netis NC63 routers. This allows attackers to extract sensitive configurations, manipulate DNS and firewall settings to intercept traffic, brick the device, or incorporate it into a botnet. While the PoC is a crash/PC-control demonstration, the primitive allows full system compromise.

## Recommendation

Prioritize the immediate isolation of management interfaces from the public internet to prevent exploitation of CVE-2026-76071.

- Audit webserver logs for large or abnormally long strings in the `destHost` parameter of POST requests to `/cgi-bin/skk_set.cgi`.
- Block inbound traffic to `/cgi-bin/skk_set.cgi` from untrusted networks at the network perimeter.
- Apply firmware updates provided by Netis if a patch for CVE-2026-76071 is released.
- Deploy detection rules targeting unauthenticated access attempts to the management CGI interface if possible in your network segment.
