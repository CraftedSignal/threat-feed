---
title: Abuse of InfDefaultInstall.exe for SCT Script Execution
slug: 2026-09-infdefaultinstall-sct-execution
description: Adversaries leverage the native Windows utility InfDefaultInstall.exe to execute malicious script content embedded within specially crafted INF files.
date: "2026-09-03T13:45:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - execution
  - windows
  - infdefaultinstall
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Adversaries leverage the native Windows utility InfDefaultInstall.exe to execute malicious script content embedded within specially crafted INF files.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md#atomic-test-4---infdefaultinstallexe-inf-execution
  - https://lolbas-project.github.io/lolbas/Binaries/Infdefaultinstall/
rules:
  - title: Detect InfDefaultInstall.exe .inf Execution
    description: Detects the execution of InfDefaultInstall.exe with an .inf file argument, often used to load SCT scripts via scrobj.dll.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM and monitor for hits.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides technical TTP for InfDefaultInstall.exe abuse.
  hunt_leads:
    - lead: Search for historical process creation events involving InfDefaultInstall.exe.
      technique_id: T1218
      data_needed:
        - Process creation telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This technique is a known LotL method for evading detection.
---

InfDefaultInstall.exe is a legitimate Microsoft-signed Windows binary designed for the installation of INF (Information) files. Threat actors can abuse this utility as a Living-off-the-Land (LotL) technique to bypass security controls. By creating a malformed or specially prepared INF file containing references to script components (SCT) via scrobj.dll, an attacker can force the system to execute arbitrary code. Because the process is signed by Microsoft, this technique is frequently utilized to evade signature-based detection mechanisms that rely on process reputation. This behavior is documented in the LOLBAS (Living Off the Land Binaries and Scripts) project and has been validated by Atomic Red Team exercises. Defenders should monitor for the execution of InfDefaultInstall.exe with arguments pointing to suspicious or user-writable INF files, as this is a known vector for initial access or persistence.

## Attack Chain

1. Attacker prepares a malicious INF file containing an InstallSection that references a remote or local SCT file.
2. Attacker crafts the INF file to utilize the RegisterOCX directive or similar hooks to load scrobj.dll.
3. Attacker delivers the malicious INF file to the victim endpoint through phishing or shared drive access.
4. Attacker executes InfDefaultInstall.exe from the command line, passing the path to the malicious INF file as an argument.
5. The Windows utility parses the INF, triggers the registration of the specified SCT script, and executes the payload.
6. The malicious payload runs within the context of the InfDefaultInstall.exe process, potentially leading to further compromise.

## Impact

Successful exploitation allows for arbitrary code execution, which can be leveraged for lateral movement, credential theft, or the deployment of secondary malware. While InfDefaultInstall.exe is a built-in utility, its misuse allows an attacker to hide malicious activity under a trusted process identity, complicating incident response and forensic analysis.

## Recommendation

* Deploy the provided Sigma rule to monitor for suspicious command-line invocations of InfDefaultInstall.exe.
* Establish a baseline of legitimate use of InfDefaultInstall.exe within the organization; alert on any unexpected paths or execution from user-writable directories (e.g., C:\Users\Public\).
* Enable Sysmon process-creation logging (Event ID 1) and command-line auditing to capture the arguments passed to InfDefaultInstall.exe.
