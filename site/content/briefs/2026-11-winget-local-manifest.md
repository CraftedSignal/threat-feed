---
brief_id: brief-2026-11-10-winget-local-manifest
event_id: brief-2026-11-10-winget-local-manifest
revision: 1
activity_at: "2026-11-10T03:08:13Z"
title: 'Microsoft Winget: Execution of local manifest installation'
slug: 2026-11-winget-local-manifest
description: Adversaries may abuse the Windows Package Manager (winget) to install arbitrary applications by passing local manifest files, potentially leading to the execution of malicious payloads.
date: "2026-11-10T03:08:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - lolbin
  - execution
  - windows
  - system-administration
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries can abuse winget to download payloads remotely and execute them.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/windows/package-manager/winget/install#local-install
  - https://lolbas-project.github.io/lolbas/Binaries/Winget/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_winget_local_install_via_manifest.yml
rules:
  - title: Detect Execution of Winget with Local Manifest
    description: Detects the use of winget to install packages via a local manifest file, a technique which can be abused to download and execute malicious payloads.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to SIEM
      owner: Detection Engineering
      due: 7d
      evidence: Rule provided in source
  hunt_leads:
    - lead: Identify all winget.exe process executions containing manifest flags in historical logs
      technique_id: T1059
      data_needed:
        - Process command line arguments
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Winget manifest capability can be abused for payload execution
---

The Windows Package Manager (winget) includes functionality to install applications using a local manifest file (YAML). This capability, while designed for administrative use and local testing, allows for the installation of software from local sources. Adversaries can leverage this feature to execute or install malicious files (such as .exe, .msi, or .msix) by providing a crafted manifest, effectively using winget as a LOLBin (Living-off-the-Land Binary) to facilitate the execution of arbitrary payloads.

## Impact

The use of this technique can result in unauthorized application installation and potential code execution on a target endpoint, depending on the contents of the local manifest and the associated payload.

## Recommendation

Deploy the provided Sigma rule to monitor process-creation events for suspicious command-line arguments involving winget. Environments that do not use local manifest installation for software deployment should treat any detection as a high-fidelity alert.
