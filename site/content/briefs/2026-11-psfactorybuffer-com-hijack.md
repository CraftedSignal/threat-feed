---
brief_id: brief-2026-11-13-psfactorybuffer-com-hijack
event_id: brief-2026-11-13-psfactorybuffer-com-hijack
revision: 1
activity_at: "2026-11-13T06:51:58Z"
title: PSFactoryBuffer COM InProcServer32 Registry Hijacking
slug: 2026-11-psfactorybuffer-com-hijack
description: The RomCom threat actor uses COM hijacking of the PSFactoryBuffer CLSID to establish persistence by redirecting execution to a malicious DLL via the InProcServer32 registry key.
date: "2026-11-13T06:51:58Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-0978
  - RomCom
  - Tropical Scorpius
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - persistence
  - privilege-escalation
  - windows
  - com-hijacking
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    subtechnique_id: T1546.015
    subtechnique_name: Component Object Model Hijacking
    evidence: This technique was used by RomCom to create persistence storing a malicious DLL.
    confidence_band: high
references:
  - https://blogs.blackberry.com/en/2023/06/romcom-resurfaces-targeting-ukraine
  - https://strontic.github.io/xcyclopedia/library/clsid_C90250F3-4D7D-4991-9B69-A5C5BC1C2AE6.html
  - https://www.trendmicro.com/en_us/research/23/e/void-rabisu-s-use-of-romcom-backdoor-shows-a-growing-shift-in-th.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_comhijack_psfactorybuffer.yml
rules:
  - title: Detect PSFactoryBuffer COM Hijacking
    description: Detects changes to the PSFactory COM InProcServer32 registry key where the default value is changed from the expected ActXPrxy.dll path.
    platform: sigma
    severity: high
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

The RomCom threat actor has been observed utilizing COM hijacking to achieve persistence on compromised Windows systems. The attack involves modifying the InProcServer32 subkey for the PSFactoryBuffer CLSID ({c90250f3-4d7d-4991-9b69-a5c5bc1c2ae6}), which is normally associated with ActXPrxy.dll. By replacing the default value with a path to a malicious DLL, attackers ensure their code is loaded by processes that initialize this COM object.

## Impact

Successful exploitation allows for the execution of code within the context of any process that loads the hijacked COM object, facilitating persistence.

## Recommendation

- Deploy the provided Sigma rule to monitor for unauthorized modifications to the PSFactoryBuffer registry key.
- Baseline legitimate registry values for InProcServer32 to identify deviations from the standard ActXPrxy.dll paths.
