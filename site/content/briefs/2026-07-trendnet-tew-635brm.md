---
title: Remote Command Injection in Trendnet TEW-635BRM Routers (CVE-2026-15481)
slug: 2026-07-trendnet-tew-635brm
description: A critical remote command injection vulnerability (CVE-2026-15481) has been discovered in Trendnet TEW-635BRM routers up to version 1.00.03, allowing attackers to execute arbitrary commands by manipulating the 'ipoa_ipaddr' argument in the 'ipoa_test' function, with public exploits available for this End-of-Life product.
date: "2026-07-12T06:20:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - remote-code-execution
  - network-device
  - EOL-product
vendors:
  - Trendnet
products:
  - TEW-635BRM (up to 1.00.03)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Performing a manipulation of the argument ipoa_ipaddr results in command injection.
    confidence_band: high
cves:
  - id: CVE-2026-15481
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15481
---

A significant security flaw, tracked as CVE-2026-15481, has been identified in Trendnet TEW-635BRM routers running firmware versions up to 1.00.03. This vulnerability, boasting a CVSS v3.1 Base Score of 8.8, is a remote command injection residing within the `ipoa_test` function of the `/sbin/rc` component, specifically through the manipulation of the `ipoa_ipaddr` argument during IPoA WAN Connection Setup. This flaw permits unauthenticated, remote attackers to execute arbitrary operating system commands on the affected device, potentially leading to full device compromise. Publicly available exploits increase the immediate risk. Trendnet has confirmed that the affected TEW-635BRM model reached End-of-Life status in 2011, indicating that no official patches will be released. This poses a severe risk to organizations still utilizing these legacy devices, as they remain perpetually vulnerable to exploitation.

## Attack Chain

1. An attacker identifies a Trendnet TEW-635BRM router (firmware up to 1.00.03) accessible remotely.
2. The attacker crafts a malicious HTTP request targeting the router's web interface or a management port.
3. The request includes a specially formed payload that manipulates the `ipoa_ipaddr` argument within the `ipoa_test` function.
4. The router's `/sbin/rc` component processes the request, executing the injected commands embedded within the `ipoa_ipaddr` argument.
5. The embedded commands are executed on the router with the privileges of the running process, typically root.
6. The attacker achieves remote code execution on the device, gaining complete control over the compromised router.

## Impact

Successful exploitation of CVE-2026-15481 grants attackers full remote command execution capabilities on the vulnerable Trendnet TEW-635BRM router. This can lead to unauthorized network access, data interception, denial of service, or the use of the compromised device as a pivot point for further attacks on the internal network. Given that public exploits are available and the product is End-of-Life without any vendor-provided patch, any organization still operating these devices faces an unmitigated, high-risk security exposure. There are no reported victim counts or specific targeted sectors, but any organization using this EOL hardware is at risk.

## Recommendation

* Immediately replace any Trendnet TEW-635BRM routers running firmware versions up to 1.00.03, as CVE-2026-15481 affects an End-of-Life product with no available patches.
* Restrict network access to administrative interfaces of all network devices to only trusted internal networks, preventing remote exploitation attempts against CVE-2026-15481.
* Conduct regular audits of network infrastructure to identify and decommission End-of-Life hardware like the Trendnet TEW-635BRM to mitigate unpatchable vulnerabilities.
