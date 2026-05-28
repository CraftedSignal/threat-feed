---
title: 'CVE-2026-46084 RDMA/mana_ib: Disable RX steering on RSS QP destroy'
slug: 2026-05-rdma-rx-steering-vuln
description: CVE-2026-46084 is a vulnerability related to RDMA/mana_ib that requires disabling RX steering on RSS QP destroy, potentially leading to denial of service or privilege escalation.
date: "2026-05-28T07:21:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - rdma
  - mana_ib
  - rss_qp
  - rx_steering
  - cve-2026-46084
vendors:
  - Microsoft
cves:
  - id: CVE-2026-46084
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-46084
rules:
  - title: Detect CVE-2026-46084 related RDMA QP Destroy events
    description: Detects events related to RDMA QP destroy, which might be related to CVE-2026-46084
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Detect potentially malicious RDMA related commands
    description: Detects potentially malicious RDMA commands
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-46084 is a vulnerability in the RDMA (Remote Direct Memory Access) subsystem, specifically within the mana_ib driver. The vulnerability stems from a failure to properly disable RX steering when an RSS QP (Receive Side Scaling Queue Pair) is destroyed. While the exact nature of the impact is not detailed in the provided source, such a flaw could potentially lead to denial of service conditions, information disclosure, or privilege escalation within the affected system. The security update addresses this issue by ensuring RX steering is correctly disabled, mitigating the risk.

## Attack Chain

1. An attacker gains initial access to a system with RDMA enabled and the vulnerable mana_ib driver loaded.
2. The attacker crafts a malicious RDMA request targeting the affected system.
3. The request triggers the creation of an RSS QP.
4. The attacker initiates a process to destroy the RSS QP without properly disabling RX steering.
5. Due to the vulnerability, RX steering remains active after QP destruction.
6. Subsequent RDMA traffic may be misdirected or processed incorrectly due to the orphaned RX steering configuration.
7. This can lead to unexpected system behavior, potentially causing a denial-of-service condition.
8. In a more sophisticated attack scenario, the attacker could leverage the vulnerability for information disclosure or privilege escalation.

## Impact

Successful exploitation of CVE-2026-46084 could lead to a denial-of-service condition, where the affected system becomes unresponsive or unstable. While the specific impact details are not provided in the source, the nature of RDMA vulnerabilities suggests potential for privilege escalation or information disclosure in certain scenarios. The number of potential victims would depend on the prevalence of systems using the affected RDMA configuration.

## Recommendation

- Apply the security update provided by Microsoft to address CVE-2026-46084 and ensure RX steering is properly disabled on RSS QP destroy.
- Deploy the Sigma rule provided below to detect attempts to exploit this vulnerability by monitoring for suspicious RDMA QP destroy events.
- Closely monitor systems with RDMA enabled for unusual network activity or system instability that could indicate exploitation attempts.
- Review RDMA configurations to ensure they adhere to security best practices and minimize the attack surface.
