---
brief_id: brief-2026-11-11-microsoft-netcore-heap-overflow-b20bbb4c
event_id: brief-2026-11-11-microsoft-netcore-heap-overflow-b20bbb4c
revision: 1
activity_at: "2026-11-11T01:54:57Z"
title: 'Microsoft .NETCore.App.Runtime: Heap-based buffer overflow in CVE-2026-114159'
slug: 2026-11-microsoft-netcore-heap-overflow-b20bbb4c
description: A heap-based buffer overflow vulnerability in Microsoft .NETCore.App.Runtime.win-x86 allows for remote code execution via network-based exploitation requiring user interaction.
date: "2026-11-11T01:54:57Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Verified against source GHSA-6rff-vv3p-7mrw.
cpes:
  - cpe:2.3:a:microsoft:microsoft_netcore_app_runtime_win_x86:*:*:*:*:*:*:*:*
vendors:
  - Microsoft
products:
  - Microsoft.NETCore.App.Runtime.win-x86 (>= 8.0.0, < 8.0.34)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Heap-based buffer overflow in Visual Studio allows an unauthorized attacker to execute code over a network.
    confidence_band: high
cves:
  - id: CVE-2026-114159
    cvss: 8.8
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-6rff-vv3p-7mrw
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114159
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-114159
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory .NET core runtime environments to identify versions < 8.0.34.
      owner: IT Operations
      due: 48h
      evidence: Affected versions listed as >= 8.0.0, < 8.0.34
  hunt_leads:
    - lead: Monitor for anomalous process execution patterns originating from processes hosting .NET runtime applications, particularly those involving network-received payloads.
      technique_id: T1203
      data_needed:
        - Process creation telemetry
        - Network connection telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves heap-based buffer overflow over a network.
  mitigation_plan:
    - priority: immediate
      action: Await and deploy the patch associated with the canonical advisory GHSA-3cgx-w6gm-fqrx.
      owner: IT Operations
      addresses: CVE-2026-114159
      evidence: Advisory withdrawn in favor of GHSA-3cgx-w6gm-fqrx.
---

Microsoft .NETCore.App.Runtime.win-x86 (versions 8.0.0 through 8.0.33) is susceptible to a heap-based buffer overflow (CWE-122) which could allow an unauthorized attacker to achieve remote code execution. This advisory, originally associated with CVE-2026-114159, has been withdrawn by GitHub as a duplicate of GHSA-3cgx-w6gm-fqrx.

## Impact
Successful exploitation allows for remote code execution with high confidentiality, integrity, and availability impact. Exploitation requires user interaction.

## Recommendation
- Inventory systems utilizing the Microsoft.NETCore.App.Runtime.win-x86 package for versions within the affected range (>= 8.0.0, < 8.0.34).
- Monitor official Microsoft security update channels for the superseding advisory (GHSA-3cgx-w6gm-fqrx) to determine the corrective patch release.
- Implement network-level egress filtering to restrict unauthorized external connections from systems running critical .NET runtime applications.
