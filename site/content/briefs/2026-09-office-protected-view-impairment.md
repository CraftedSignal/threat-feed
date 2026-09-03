---
title: Detection of Microsoft Office Protected View Disablement
slug: 2026-09-office-protected-view-impairment
description: Adversaries modify registry keys to disable Microsoft Office Protected View security controls, facilitating the execution of malicious documents.
date: "2026-09-01T12:12:40Z"
lastmod: "2026-09-03T13:36:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-impairment
  - registry-tampering
  - microsoft-office
  - persistence
  - privilege-escalation
  - registry
  - windows
  - office
vendors:
  - Microsoft
products:
  - Microsoft Office
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Adversaries may modify these keys to execute malicious code when Office files are opened.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_disable_protected_view_features.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
  - https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/
rules:
  - title: Detect Microsoft Office Protected View Disablement
    description: Detects changes to Microsoft Office protected view registry keys indicating that the security feature is being disabled.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - registry_set
      - windows
  - title: Detect Office Autorun Keys Modification
    description: Detects unauthorized modification of Office application registry keys used to load add-ins.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the registry monitoring rule and monitor for the specific keys identified.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides technical registry paths.
  hunt_leads:
    - lead: Search for historical registry set events (Event ID 13) matching Office ProtectedView paths.
      technique_id: T1685
      data_needed:
        - Registry modification logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Sigma source provided explicit registry paths.
  mitigation_plan:
    - priority: medium
      action: Use Group Policy Objects (GPO) to enforce Protected View settings and prevent user/script-based modifications.
      owner: IT Operations
      addresses: Defense Impairment
      evidence: Standard security hardening practice for Office.
updates:
  - at: "2026-09-03T13:36:26Z"
    level: L1
    summary: 'added detection rule: Detect Office Autorun Keys Modification'
    sources:
      - sigma-hq
    source_urls:
      - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_office.yml
---

Attackers frequently modify Windows Registry keys related to Microsoft Office security configurations to impair defensive controls. Specifically, by disabling 'Protected View', threat actors ensure that malicious documents, once downloaded or opened, bypass the sandbox environment designed to restrict code execution from untrusted sources. This technique, observed in campaigns by actors such as Gorgon Group, enables the successful execution of macro-based malware or exploits contained within document files. This behavior is a form of defense impairment that allows an attacker to proceed with malicious activity after initial access, effectively neutralizing a critical layer of defense provided by Microsoft Office security policies.

## Attack Chain

1. Attacker sends a malicious Office document via spearphishing or direct download.
2. Victim receives the document or saves it to a local drive.
3. Attacker executes a secondary dropper or script on the host machine.
4. Script modifies HKEY_CURRENT_USER registry keys associated with Office Protected View (e.g., DisableInternetFilesInPV).
5. The integrity of the sandbox environment is removed by setting the specific registry values to disable safety checks.
6. Victim opens the malicious document, which executes macros or embedded code without being restricted by Protected View.
7. Final payload (malware) achieves execution and initiates command and control (C2).

## Impact

Disabling Protected View significantly lowers the barrier for malware execution on Windows endpoints. Successful exploitation allows for the full compromise of the user session, credential theft, and potential lateral movement within the network. This technique is commonly leveraged as a precursor to ransomware deployment or long-term persistent espionage activities.

## Recommendation

Deploy the provided Sigma rule to monitor for registry modifications related to Office security features. Block administrative scripts that attempt to modify these specific keys under HKCU/Software/Microsoft/Office. Monitor for anomalous execution of office-related processes immediately following registry changes to these specific paths.
