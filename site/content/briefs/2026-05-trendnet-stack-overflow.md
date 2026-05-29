---
title: TRENDnet TEW-432BRP Stack-Based Buffer Overflow Vulnerability (CVE-2026-10062)
slug: 2026-05-trendnet-stack-overflow
description: TRENDnet TEW-432BRP version 3.10B20 is vulnerable to a stack-based buffer overflow via manipulation of the ip/mask/gateway arguments in the formSetRoute function of the /goform/formSetRoute file, enabling remote attackers to potentially execute arbitrary code.
date: "2026-05-29T15:18:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - buffer-overflow
  - router
vendors:
  - TRENDnet
products:
  - TEW-432BRP 3.10B20
cves:
  - id: CVE-2026-10062
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10062
  - CVE-2026-10062
rules:
  - title: Detects CVE-2026-10062 Exploitation Attempt — Malicious request to formSetRoute
    description: Detects CVE-2026-10062 exploitation attempt — HTTP POST request to /goform/formSetRoute with unusually long parameters, indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-10062 Exploitation Attempt — Suspicious Characters in formSetRoute
    description: Detects CVE-2026-10062 exploitation attempt by identifying potentially malicious characters in the request to formSetRoute.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-10062 describes a stack-based buffer overflow vulnerability affecting TRENDnet TEW-432BRP router, version 3.10B20. The vulnerability resides within the `formSetRoute` function of the `/goform/formSetRoute` file. By manipulating the `ip`, `mask`, and `gateway` arguments, a remote attacker can trigger a buffer overflow, potentially leading to arbitrary code execution. This vulnerability is remotely exploitable and has a public exploit available. However, TRENDnet has stated that the affected product has been End-of-Life (EOL) since 2009 and will not be patched. Defenders need to identify and isolate instances of this legacy hardware.

## Attack Chain

1.  The attacker identifies a vulnerable TRENDnet TEW-432BRP router running firmware version 3.10B20.
2.  The attacker sends a crafted HTTP POST request to the `/goform/formSetRoute` endpoint.
3.  The POST request includes oversized values for the `ip`, `mask`, and/or `gateway` parameters.
4.  The `formSetRoute` function processes the request without proper bounds checking.
5.  The oversized input overflows a stack buffer allocated for these parameters.
6.  The buffer overflow overwrites adjacent memory on the stack, including the return address.
7.  The function returns, transferring control to the attacker-controlled address.
8.  The attacker executes arbitrary code on the router, potentially gaining complete control.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the affected TRENDnet TEW-432BRP router. Given the device's End-of-Life status since 2009, a patch is not available. Compromise of the router could lead to network disruption, data theft, or the router being used as a botnet node. While the precise number of vulnerable devices is unknown, any organization still using this model is at significant risk.

## Recommendation

*   Identify and isolate any TRENDnet TEW-432BRP 3.10B20 devices on your network (see affected products).
*   If these devices are business-critical, consider placing them behind a firewall with strict access control lists and intrusion prevention systems.
*   Deploy the Sigma rules to detect potential exploitation attempts against the `/goform/formSetRoute` endpoint.
*   Monitor web server logs (category: webserver) for unusual activity targeting the `/goform/formSetRoute` path.
*   Consider network segmentation to limit the potential impact of a compromised device.
