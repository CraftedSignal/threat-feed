---
brief_id: brief-2026-11-04-xwizard-com-exec
event_id: brief-2026-11-04-xwizard-com-exec
revision: 2
activity_at: "2026-11-05T10:05:31Z"
revision_history:
  - revision: 2
    at: "2026-11-05T10:05:31Z"
    checksum: sha256:2b5f1bc431853a09af426cd6e57f091bafa51565fd6c97edff8e108fa5732dd9
    summary: new product
    changed_fields:
      - affected_products
      - affected_vendors
      - claim_state
      - lastmod
      - updates
    source_urls:
      - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_xwizard_runwizard_com_object_exec.yml
title: 'Living-off-the-Land: Xwizard.exe COM object execution'
slug: 2026-11-xwizard-com-exec
description: Xwizard.exe can be abused to execute arbitrary COM objects via the RunWizard command line argument, facilitating stealthy execution of malicious code.
date: "2026-11-04T03:53:30Z"
lastmod: "2026-11-05T10:04:55Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Rule syntax verified against Sigma standards
tags:
  - living-off-the-land
  - execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This utility can be abused in order to run custom COM object created in the registry.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
  - https://www.elastic.co/guide/en/security/current/execution-of-com-object-via-xwizard.html
  - https://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_xwizard_runwizard_com_object_exec.yml
rules:
  - title: Detect COM Object Execution via Xwizard.exe
    description: Detects the execution of Xwizard.exe with the 'RunWizard' flag and a GUID-like argument, indicative of COM object execution abuse.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for Xwizard.exe executions in process telemetry
      technique_id: T1218
      data_needed:
        - Process creation events (Event ID 1)
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Xwizard.exe is a known LOLBAS binary that can be abused for proxy execution.
updates:
  - at: "2026-11-05T10:04:55Z"
    level: L1
    summary: new product
    sources:
      - sigma-hq
    source_urls:
      - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_xwizard_runwizard_com_object_exec.yml
---

Xwizard.exe is a legitimate Windows utility that can be leveraged to execute COM objects specified in the Windows registry. Threat actors may abuse this functionality by invoking the tool with the "RunWizard" command line argument followed by a specific Class ID (CLSID) to execute arbitrary code or payloads.

## Impact
Execution of arbitrary COM objects can lead to code execution under the context of the user running the utility, potentially allowing for persistence or evasion of traditional signature-based security controls by utilizing a signed Microsoft binary.

## Recommendation
- Deploy the provided Sigma rule to detect suspicious Xwizard execution patterns in process creation logs.
- Baseline legitimate usage of Xwizard.exe in your environment to distinguish between system activity and potential abuse.
- Monitor registry modifications (e.g., CLSID keys) that correlate with unexpected process spawns involving Xwizard.
