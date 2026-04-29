---
title: D-Link DIR-605L Router Buffer Overflow Vulnerability
slug: 2026-04-dlink-dir605l-bo
description: A remote buffer overflow vulnerability exists in the D-Link DIR-605L version 2.13B01 due to improper handling of the 'curTime' argument in the '/goform/formVirtualServ' POST request handler, potentially allowing attackers to execute arbitrary code.
date: "2026-04-09T21:16:13Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - dlink
  - router
  - buffer_overflow
  - cve-2026-5979
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5979
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5979
  - https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formVirtualServ-33153a41781f80b496e1de206077bc7e?source=copy_link
  - https://vuldb.com/submit/791852
  - https://vuldb.com/vuln/356533
  - https://vuldb.com/vuln/356533/cti
  - https://www.dlink.com/
rules:
  - title: Detect Suspiciously Long curTime Parameter in D-Link Routers
    description: Detects unusually long 'curTime' parameters in requests to '/goform/formVirtualServ', potentially indicating a buffer overflow attempt on D-Link routers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connections from D-Link Routers
    description: Detects unusual outbound network connections originating from D-Link routers, potentially indicating a compromised device.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

A buffer overflow vulnerability, CVE-2026-5979, has been identified in D-Link DIR-605L router with firmware version 2.13B01. The vulnerability resides in the `formVirtualServ` function within the `/goform/formVirtualServ` component, specifically within the POST request handler. By manipulating the `curTime` argument, a remote attacker can trigger a buffer overflow. According to the NVD, an exploit is publicly available, increasing the risk of exploitation. This vulnerability affects end-of-life products, making patching impossible.

## Attack Chain

1.  Attacker identifies a vulnerable D-Link DIR-605L router running firmware 2.13B01.
2.  Attacker crafts a malicious HTTP POST request targeting the `/goform/formVirtualServ` endpoint.
3.  The POST request includes the `curTime` argument with a value exceeding the buffer's capacity.
4.  The router's `formVirtualServ` function processes the POST request without proper bounds checking.
5.  The oversized `curTime` value overwrites adjacent memory regions on the stack or heap.
6.  The attacker carefully crafts the overflow payload to overwrite the return address.
7.  Upon returning from the `formVirtualServ` function, control is transferred to the attacker-controlled address.
8.  The attacker executes arbitrary code on the router, potentially gaining full control.

## Impact

Successful exploitation of this buffer overflow vulnerability (CVE-2026-5979) can lead to complete compromise of the D-Link DIR-605L router. Attackers could potentially execute arbitrary code, enabling them to modify router settings, intercept network traffic, or use the compromised device as a pivot point for further attacks within the network. Due to the product being end-of-life, a patch is not available. The number of vulnerable devices is unknown.

## Recommendation

*   Monitor webserver logs for requests to `/goform/formVirtualServ` with unusually long `curTime` parameters to detect potential exploitation attempts (see Sigma rule "Detect Suspiciously Long curTime Parameter in D-Link Routers").
*   Implement network intrusion detection system (IDS) rules to detect suspicious traffic patterns associated with buffer overflow exploits targeting web interfaces.
*   Since this device is end-of-life, consider replacing the D-Link DIR-605L router with a supported model to mitigate the risk, as there will be no patches issued.
*   Examine network traffic for unusual outbound connections originating from D-Link DIR-605L routers to identify potentially compromised devices (see Sigma rule "Detect Outbound Connections from D-Link Routers").
