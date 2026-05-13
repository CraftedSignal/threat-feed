---
title: BIG-IP PEM iRules Traffic Management Microkernel (TMM) Termination
slug: 2026-05-big-ip-pem-tmm-termination
description: CVE-2026-41218 describes a vulnerability in F5 BIG-IP PEM iRules where undisclosed traffic can cause the Traffic Management Microkernel (TMM) to terminate, leading to a denial-of-service condition.
date: "2026-05-13T16:24:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - dos
  - f5
  - big-ip
vendors:
  - F5 Networks
products:
  - BIG-IP PEM iRules
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
cves:
  - id: CVE-2026-41218
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41218
  - https://my.f5.com/manage/s/article/K000160875
rules:
  - title: Detect BIG-IP PEM iRules TMM Termination Attempt
    description: Detects CVE-2026-41218 exploitation attempt by identifying traffic targeting vulnerable BIG-IP PEM iRules commands.
    platform: sigma
    severity: high
    tactics:
      - dos
      - exploitation
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - f5_big-ip
rules_count: 1
---

CVE-2026-41218 describes a vulnerability affecting F5 BIG-IP Policy Enforcement Manager (PEM) iRules. When specific iRules commands are configured on a virtual server (iRules using commands starting with `CLASSIFICATION::`, `CLASSIFY::`, `PEM::`, `PSC::`, and the `urlcatquery` command), specially crafted, undisclosed traffic can trigger a termination of the Traffic Management Microkernel (TMM). The vulnerability leads to a denial-of-service condition. This issue does not affect software versions that have reached End of Technical Support (EoTS). The vulnerability was reported by F5 Networks.

## Attack Chain

1. An attacker identifies a vulnerable BIG-IP system with PEM iRules configured.
2. The attacker crafts malicious network traffic.
3. The malicious traffic is sent to the BIG-IP virtual server.
4. The iRule processes the malicious traffic, specifically using vulnerable commands like `CLASSIFICATION::`, `CLASSIFY::`, `PEM::`, `PSC::`, or `urlcatquery`.
5. The processing of the crafted traffic causes a use-after-free condition in the TMM.
6. The TMM process crashes due to the memory corruption.
7. The BIG-IP system experiences a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-41218 results in the termination of the Traffic Management Microkernel (TMM), leading to a denial-of-service condition. This impacts the availability of services relying on the BIG-IP system. The severity is rated as High with a CVSS v3.1 score of 7.5.

## Recommendation

*   Monitor network traffic for patterns exploiting the `CLASSIFICATION::`, `CLASSIFY::`, `PEM::`, `PSC::`, and `urlcatquery` commands in iRules as described in the vulnerability details for CVE-2026-41218.
*   Deploy the Sigma rule `Detect BIG-IP PEM iRules TMM Termination Attempt` to detect potential exploitation attempts by analyzing network traffic targeting the BIG-IP system.
*   Refer to F5 Networks advisory K000160875 for mitigation steps and affected versions.
