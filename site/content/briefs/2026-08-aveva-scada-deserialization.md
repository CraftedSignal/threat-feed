---
title: AVEVA Enterprise SCADA Deserialization Vulnerability
slug: 2026-08-aveva-scada-deserialization
description: Authenticated attackers with operator-level access can exploit a deserialization vulnerability (CVE-2025-7639) in AVEVA Enterprise SCADA to achieve remote code execution.
date: "2026-08-13T16:53:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - scada
  - deserialization
  - cve-2025-7639
vendors:
  - AVEVA
products:
  - Enterprise SCADA 2025
  - Enterprise SCADA 2024
  - Enterprise SCADA 2023
  - Enterprise SCADA 2022
  - Enterprise SCADA 2021
  - Enterprise SCADA HMI
  - Pipeline Operations for Gas/Liquids
  - Pipeline Integrity Monitor
  - Pipeline Training Simulator
  - Measurement Advisor
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Successful exploitation of this vulnerability could allow an attacker to tamper with serialized data, potentially resulting in code execution during deserialization.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-01
  - https://www.cve.org/CVERecord?id=CVE-2025-7639
  - https://softwaresupportsp.aveva.com/en-US/knowledge/details/000117814?lang=en_US
  - https://www.aveva.com/content/dam/aveva/documents/support/cyber-security-updates/SecurityBulletin_AVEVA-2026-005.pdf
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Upgrade affected AVEVA Enterprise SCADA servers and clients to versions specified in AVEVA-2026-005
      owner: IT Operations
      due: 72h
      evidence: Vendor remediation guidance in ICSA-26-225-01
  mitigation_plan:
    - priority: immediate
      action: Change BinarySerializer mode to JSON and disable AcceptBinaryFormattedData
      owner: OT Security
      addresses: CVE-2025-7639
      evidence: Configuration remediation steps in KB117814
---

AVEVA has identified a high-severity deserialization vulnerability, tracked as CVE-2025-7639, affecting multiple versions of the AVEVA Enterprise SCADA suite. The vulnerability exists within the application's handling of serialized data, specifically when using the 'Binary Formatter' mode. An authenticated attacker possessing 'DNA Authority - Operator' privileges can manipulate serialized data streams to force the application to execute arbitrary code under the security context of the 'DNA Apps' service group. 

This issue impacts a wide range of versions, including the 2025 release and various service packs of the 2021 through 2024 versions. Because this affects critical infrastructure sectors and involves code execution, it poses a significant risk to industrial operations. AVEVA has released security updates and recommended configuration changes, including the migration from Binary Formatter to JSON serialization, to remediate the vulnerability.

## Impact

Successful exploitation allows an attacker to achieve remote code execution within the 'DNA Apps' security group context. This could lead to full control over affected SCADA servers and HMI clients, potentially enabling unauthorized process control or disruption of critical manufacturing operations globally.

## Recommendation

- Upgrade all affected Server and Client nodes to the versions specified in AVEVA Security Bulletin AVEVA-2026-005.
- Implement the recommended configuration changes by updating 'BinarySerializer' mode settings from 'Binary Formatter' to 'JSON' and disabling 'AcceptBinaryFormattedData'.
- Audit assigned permissions to ensure that only authorized personnel maintain 'DNA Authority - Operator' privileges.
- Disable any 'BLT Test' clients currently running within production environments as per vendor guidance.
- Review KB117814 for detailed step-by-step instructions on migration and configuration hardening.
