---
title: CVE-2026-56297 - FreeRDP Use-After-Free Vulnerability Leading to RCE/DoS
slug: 2026-07-freerdp-use-after-free
description: A use-after-free vulnerability (CVE-2026-56297) in the FreeRDP client before version 3.22.0 allows a malicious RDP server to achieve remote code execution or denial of service on connecting clients by triggering a race condition through concurrent DYNVC_DATA and DYNVC_CLOSE messages.
date: "2026-07-08T14:23:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - RCE
  - DoS
  - FreeRDP
  - client-side
vendors:
  - FreeRDP
products:
  - FreeRDP < 3.22.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: potentially enabling remote code execution
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: potentially enabling remote code execution or denial of service
    confidence_band: high
cves:
  - id: CVE-2026-56297
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56297
  - https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-3mv2-5q57-2v8h
  - https://www.vulncheck.com/advisories/freerdp-use-after-free-via-race-condition-in-drdynvc-channel-callback
---

CVE-2026-56297 describes a critical use-after-free vulnerability affecting FreeRDP client versions prior to 3.22.0. This flaw, residing within the `dvcman_channel_close` and `dvcman_call_on_receive` functions, arises from improper synchronization of `channel_callback` access. An attacker can exploit this by operating a malicious RDP server, which sends specially crafted `DYNVC_DATA` and `DYNVC_CLOSE` messages concurrently. This race condition leads to a heap-use-after-free condition in the `drdynvc` client thread, potentially resulting in remote code execution (RCE) or a denial of service (DoS) on the connecting FreeRDP client. The vulnerability was published on July 8, 2026, and impacts users of the FreeRDP client library. Defenders should prioritize patching and be aware of malicious RDP servers targeting their FreeRDP-enabled endpoints.

## Attack Chain

1. The victim uses a FreeRDP client version prior to 3.22.0 to connect to a malicious RDP server.
2. The malicious RDP server initiates dynamic virtual channel (DYNVC) communication with the client.
3. The server crafts and sends `DYNVC_DATA` and `DYNVC_CLOSE` messages concurrently to the client.
4. Due to improper synchronization within `dvcman_channel_close` and `dvcman_call_on_receive`, a race condition is triggered in the FreeRDP client's `drdynvc` thread.
5. This race condition causes a heap-use-after-free error within the client's memory.
6. The malicious RDP server can leverage this memory corruption to achieve remote code execution on the client, or simply cause the client application to crash, leading to a denial of service.

## Impact

A successful exploitation of CVE-2026-56297 can lead to severe consequences for organizations utilizing vulnerable FreeRDP clients. Attackers controlling a malicious RDP server could execute arbitrary code on the client machine, potentially leading to full system compromise, data exfiltration, or further network lateral movement. Alternatively, they could trigger a denial of service, rendering the FreeRDP client application unusable and disrupting user access to legitimate RDP sessions. While no specific victim counts or targeted sectors are mentioned, any organization whose users connect to untrusted RDP servers via affected FreeRDP clients is at risk.

## Recommendation

* Immediately upgrade all FreeRDP client installations to version 3.22.0 or later to patch CVE-2026-56297.
* Implement strict policies and controls on which RDP servers users are permitted to connect to, especially when using FreeRDP clients.
