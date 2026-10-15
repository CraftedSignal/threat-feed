---
title: Remote Heap-Based Buffer Overflow in Wavlink WN530HG4B
slug: 2026-10-wavlink-heap-overflow
description: A heap-based buffer overflow in the api.cgi component of Wavlink WN530HG4B firmware allows unauthenticated remote attackers to execute arbitrary code via malformed input to the api=info&client=app handler.
date: "2026-10-15T16:39:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:wavlink:wn530hg4b:m30hg4b_v260724:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - buffer-overflow
  - network-security
  - firmware-vulnerability
vendors:
  - Wavlink
products:
  - WN530HG4B (< 2026-09-24-841a51c6d5_tclinux.bin)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation results in heap-based buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-110958
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110958
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade firmware to 2026-09-24-841a51c6d5_tclinux.bin on all affected WN530HG4B units
      owner: IT Operations
      due: 24h
      evidence: Vendor recommendation for remediation
  mitigation_plan:
    - priority: immediate
      action: Firewall off management access to api.cgi from non-trusted networks
      owner: IT Operations
      addresses: CVE-2026-110958
      evidence: Remote exploitability of the api.cgi endpoint
---

A critical vulnerability (CVE-2026-110958) has been identified in the Wavlink WN530HG4B router, specifically within the firmware version M30HG4B_V260724. The vulnerability manifests in the api.cgi handler, where insecure processing of the api=info&client=app request leads to a heap-based buffer overflow. Historically, the firmware utilized the system() function to process these requests, creating a pathway for command injection and memory corruption.

The vendor has acknowledged the flaw and issued a firmware update (2026-09-24-841a51c6d5_tclinux.bin) to remediate the issue. The patch transitions the login script execution from system() to execvp and introduces strict length-limiting and null-checking for client address inputs. Public exploit code for this vulnerability is available, posing a high risk to unpatched devices exposed to the internet. Defenders should prioritize firmware upgrades and isolate vulnerable management interfaces from public networks.

## Impact

Successful exploitation of CVE-2026-110958 allows unauthenticated remote attackers to trigger a heap-based buffer overflow. This can result in arbitrary code execution on the affected network device. Given the device's role as a network router, successful exploitation grants the attacker persistent control over the network gateway, enabling traffic interception, lateral movement, or complete device compromise. The CVSS base score of 10.0 reflects the high severity and ease of exploitation for remote, unauthenticated actors.

## Recommendation

* Immediately upgrade all Wavlink WN530HG4B devices to firmware version 2026-09-24-841a51c6d5_tclinux.bin.
* Restrict access to the device management interface (api.cgi) to trusted internal subnets or local console access only.
* Monitor network traffic for anomalous HTTP POST or GET requests targeting /api.cgi with abnormally long strings in the 'client' parameter.
