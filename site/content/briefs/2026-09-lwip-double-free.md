---
title: Double Free Vulnerability in lwIP (Lightweight IP)
slug: 2026-09-lwip-double-free
description: The lwIP TCP/IP stack contains a double free vulnerability (CVE-2026-91018) that could allow an attacker with adjacent network access to trigger memory corruption or remote code execution.
date: "2026-09-22T16:46:52Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - lwIP
products:
  - lwIP (Lightweight IP) (>=2.0.1, <=2.2.1)
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-02
  - https://www.cve.org/CVERecord?id=CVE-2026-91018
  - https://cgit.git.savannah.gnu.org/cgit/lwip.git
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Architecture
  immediate_actions:
    - action: Inventory embedded assets running lwIP and identify those using versions 2.0.1 through 2.2.1.
      owner: IT Operations
      due: 72h
      evidence: Source advisory identifies specific affected version range.
  mitigation_plan:
    - priority: immediate
      action: Upgrade lwIP to a non-vulnerable version using commit f873b6295933e4149a2132adf3e9a2d2a676a5ec.
      owner: IT Operations
      addresses: CVE-2026-91018
      evidence: Remediation section of CISA advisory.
---

lwIP (Lightweight IP) is a widely deployed open-source TCP/IP stack intended for embedded systems. A double free vulnerability, identified as CVE-2026-91018, exists in the API implementation of lwIP versions 2.0.1 through 2.2.1. This vulnerability arises from improper handling of memory allocation, specifically a double free condition (CWE-415). An attacker capable of sending specifically crafted packets from an adjacent network segment can exploit this flaw. Successful exploitation can lead to a system crash, denial of service, memory corruption, or arbitrary code execution on the target device. Given the widespread use of lwIP in critical infrastructure sectors - including energy, water, healthcare, and industrial control systems - this vulnerability poses a significant risk to the integrity and availability of embedded network hardware.

## Impact

Successful exploitation of CVE-2026-91018 can result in complete system compromise or persistent denial of service in embedded devices. Because lwIP is integrated into numerous industrial and communications products globally, the scope of potentially vulnerable assets is extensive across critical infrastructure sectors such as energy, water, and manufacturing. If exploited, an attacker could achieve arbitrary code execution, bypassing safety controls or exfiltrating sensitive operational data.

## Recommendation

- Upgrade the lwIP library to a patched version using the source repository provided at https://cgit.git.savannah.gnu.org/cgit/lwip.git.
- Apply the specific fix identified by commit hash f873b6295933e4149a2132adf3e9a2d2a676a5ec.
- Isolate embedded control system devices from business networks and ensure they are not directly accessible via the public internet.
- Implement network-level segmentation to restrict access to the affected devices, limiting communication to authorized, trusted adjacent network segments only.
- Deploy VPNs for required remote access, ensuring the VPN infrastructure itself is patched and hardened against exploitation.
