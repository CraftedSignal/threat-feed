---
title: DoS Vulnerability in Juniper Networks Junos OS netsctp.ko
slug: 2026-10-netsctp-dos
description: An infinite loop vulnerability (CVE-2026-102046) in the netsctp.ko kernel module of Juniper Junos OS allows unauthenticated remote attackers to cause a denial of service on MX Series devices via crafted SCTP traffic.
date: "2026-10-14T18:39:44Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*
vendors:
  - Juniper Networks
products:
  - Junos OS (MX Series)
cves:
  - id: CVE-2026-102046
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102046
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Engineering
  immediate_actions:
    - action: Inventory all Juniper MX Series devices and check for pending security patches
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-102046 affects Juniper MX Series devices
  mitigation_plan:
    - priority: immediate
      action: Apply firmware updates from Juniper Networks to resolve CVE-2026-102046
      owner: Network Engineering
      addresses: CVE-2026-102046
      evidence: Source identified vulnerable kernel module in Junos OS
---

A vulnerability identified as CVE-2026-102046 affects the netsctp.ko kernel module within Juniper Networks Junos OS on MX Series platforms. This flaw is classified as a Loop with Unreachable Exit Condition, which can be exploited by an unauthenticated network attacker sending specially crafted SCTP (Stream Control Transmission Protocol) packets. When processed by the netsctp.ko module, these packets trigger an infinite loop that causes significant resource exhaustion, ultimately resulting in a system crash or permanent denial of service condition. This vulnerability poses a high risk to availability for network infrastructure relying on MX Series devices, as it requires no prior authentication and can be triggered remotely. Defenders should monitor for unexpected SCTP traffic patterns or device instability in environments utilizing affected versions of Junos OS.

## Impact

Successful exploitation leads to a complete denial of service for affected Juniper MX Series devices. This disruption can halt critical routing and switching operations, impacting network availability for organizations relying on this hardware. As of the current disclosure, the scope of targeting remains global for any internet-facing or reachable MX Series router running a vulnerable version of Junos OS.

## Recommendation

Prioritize the identification of all Juniper MX Series devices currently operating in the environment. Apply vendor-provided security patches or firmware updates addressing CVE-2026-102046 as soon as they are made available by Juniper Networks. Monitor device health and system resource telemetry for sudden spikes in CPU utilization or kernel panics specifically linked to SCTP packet processing.
