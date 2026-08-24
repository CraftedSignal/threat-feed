---
title: Remote Code Execution via Out-of-Bounds Write in libwebsockets LECP Component
slug: 2026-08-libwebsockets-oob
description: An out-of-bounds write vulnerability in the libwebsockets LECP CBOR recording function (CVE-2026-78161) allows remote attackers to trigger memory corruption via crafted CBOR data.
date: "2026-08-24T01:40:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - cbor
vendors:
  - warmcat
products:
  - libwebsockets
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-78161
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78161
  - https://github.com/warmcat/libwebsockets/commit/1d44554a1bb262db63ff4e240152a9deecd99054
  - https://github.com/biniamf/pocs/tree/main/libwebsockets-lecp-lecp_parse-cbor_pos_oob_write
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch libwebsockets to versions containing the fix for CVE-2026-78161.
      owner: IT Operations
      due: 48h
      evidence: Best practice to apply a patch to resolve this issue.
  hunt_leads:
    - lead: Identify applications linking against libwebsockets 4.5.0.
      technique_id: T1190
      data_needed:
        - Software inventory / SBOM
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Impacted is warmcat libwebsockets 4.5.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade or patch libwebsockets components.
      owner: IT Operations
      addresses: CVE-2026-78161
      evidence: Patch is identified as 1d44554a1bb262db63ff4e240152a9deecd99054.
---

A memory corruption vulnerability has been identified in the warmcat libwebsockets library, specifically within the LECP (Lightweight Embedded CBOR Parser) component. The flaw exists in the report_raw_cbor function located in lib/misc/lecp.c in version 4.5.0. An attacker can exploit this vulnerability remotely by supplying a specially crafted CBOR payload to an application utilizing the libwebsockets library. This manipulation results in an out-of-bounds write, which may lead to application instability, service disruption, or potentially arbitrary code execution depending on the memory layout and the implementation of the host application. A proof-of-concept exploit has been made public, increasing the risk of exploitation for unpatched systems. Organizations utilizing libwebsockets 4.5.0 should prioritize updating to a patched version or applying the official vendor commit 1d44554a1bb262db63ff4e240152a9deecd99054.

## Attack Chain

1. The attacker performs reconnaissance to identify services or applications utilizing the libwebsockets library version 4.5.0.
2. The attacker crafts a malicious CBOR (Concise Binary Object Representation) payload designed to trigger the out-of-bounds write in the report_raw_cbor function.
3. The attacker transmits the payload to the target application via the established web socket or network interface.
4. The libwebsockets library receives the data and passes it to the lecp_parse function for processing within the LECP component.
5. The function report_raw_cbor performs an insecure write operation due to insufficient bounds checking on the CBOR input.
6. The out-of-bounds write corrupts adjacent memory regions within the application process space.
7. The attacker leverages the corrupted memory state to achieve a crash or redirect application execution flow.
8. Final objective achieved, typically resulting in Denial of Service (DoS) or Remote Code Execution (RCE).

## Impact

Successful exploitation of CVE-2026-78161 allows a remote, unauthenticated attacker to cause memory corruption in systems using libwebsockets 4.5.0. Given the library's prevalence in embedded devices and networked applications, this poses a high risk to availability and system integrity. While the severity is documented as high (CVSS 7.3), the real-world impact depends on the specific host application's memory protections and the attacker's ability to weaponize the memory corruption for reliable execution.

## Recommendation

* Apply the official patch identified by commit 1d44554a1bb262db63ff4e240152a9deecd99054 to all instances of libwebsockets 4.5.0 immediately.
* Identify applications within the environment that dynamically link against libwebsockets 4.5.0 and schedule emergency patching.
* Monitor network traffic for anomalous CBOR payloads if the environment has known exposure of internal services using this library to the internet.
* Review development build pipelines to ensure static compilation of libwebsockets does not include the vulnerable 4.5.0 version.
