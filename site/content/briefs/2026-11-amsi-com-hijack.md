---
brief_id: brief-2026-11-13-amsi-com-hijack
event_id: brief-2026-11-13-amsi-com-hijack
revision: 1
activity_at: "2026-11-13T06:51:29Z"
title: AMSI COM Server Hijacking
slug: 2026-11-amsi-com-hijack
description: An adversary can disable Microsoft Antimalware Scan Interface (AMSI) scanning capabilities by hijacking the COM server registry key used during AMSI initialization, causing the component to fail load.
date: "2026-11-13T06:51:29Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_amsi_com_hijack.yml
  - https://enigma0x3.net/2017/07/19/bypassing-amsi-via-com-server-hijacking/
rules:
  - title: Potential AMSI COM Server Hijacking
    description: Detects unauthorized modifications to the AMSI COM server registry key used to disable AMSI scanning.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect unauthorized modifications to the AMSI COM server registry key.
      owner: Detection Engineering
      due: 24h
      evidence: Rule detection logic targets registry modification of specific CLSID.
---

Attackers can bypass AMSI by modifying the registry key associated with its COM server (CLSID {fdb00e52-a214-4aa1-8fba-4357bb0072ec}). When the COM server is redirected to a non-existent location, the AMSI component fails to load, rendering the security scanning interface useless for the compromised process.

## Impact

Successful exploitation results in the complete disabling of AMSI for affected processes, allowing malicious scripts and payloads to execute without being scanned or intercepted by security tools that rely on AMSI integration.

## Recommendation

Detection teams should monitor registry modifications to the AMSI COM server CLSID. Deploy the provided Sigma rule to alert on any modification where the default InProcServer32 value is not the legitimate amsi.dll.
