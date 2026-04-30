---
title: Persistence via Visual Studio Tools for Office (VSTO) Add-ins
slug: 2024-01-vsto-persistence
description: The Visual Studio Tools for Office (VSTO) add-ins can be abused by attackers to establish persistence in Microsoft Office applications by modifying registry keys.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - office
  - vsto
vendors:
  - Microsoft
products:
  - Microsoft Office
  - Microsoft Visual Studio
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
references:
  - https://twitter.com/_vivami/status/1347925307643355138
  - https://vanmieghem.io/stealth-outlook-persistence/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_office_vsto.yml
rules:
  - title: Suspicious VSTOInstaller Process Creation
    description: Detects suspicious process creations involving VSTOInstaller.exe which may indicate malicious VSTO add-in installations.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137.006
    data_sources:
      - process_creation
      - windows
  - title: Registry Modification for VSTO Add-in Persistence
    description: Detects registry modifications related to VSTO add-ins, specifically targeting the LoadBehavior value.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137.006
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers can leverage Visual Studio Tools for Office (VSTO) add-ins to establish persistence within Microsoft Office applications. VSTO add-ins, designed to extend the functionality of Office applications, can be manipulated by threat actors to execute malicious code upon application startup. By modifying specific registry keys associated with VSTO add-ins, adversaries can ensure their code is loaded and executed each time an Office application is launched. This technique allows for covert and persistent access to compromised systems, enabling further malicious activities such as data exfiltration, lateral movement, or the deployment of additional payloads. The detection of this persistence mechanism is crucial for defenders to identify and mitigate potential compromises within their environment.

## Attack Chain

1.  Attacker gains initial access to the target system via unspecified means (e.g., phishing, exploiting a vulnerability).
2.  The attacker identifies the registry keys associated with VSTO add-ins for Office applications (Outlook, Word, Excel, PowerPoint). These keys are typically located under `\Software\Microsoft\Office\[Application]\Addins\`.
3.  The attacker modifies the registry to add or modify entries related to a malicious VSTO add-in. This involves setting the `LoadBehavior` value to `3` to ensure the add-in is loaded on startup.
4.  The attacker places the malicious VSTO add-in files (DLLs) in a location accessible to the Office application.
5.  The attacker may also modify the `\Software\Microsoft\VSTO\Security\Inclusion\` registry key to bypass security warnings related to unsigned add-ins.
6.  The user launches the targeted Office application (e.g., Outlook).
7.  The Office application loads the malicious VSTO add-in based on the modified registry entries.
8.  The malicious VSTO add-in executes its payload, enabling the attacker to perform malicious activities on the system.

## Impact

Successful exploitation allows attackers to achieve persistent code execution within Microsoft Office applications. This can lead to the compromise of sensitive data, the deployment of additional malware, and the establishment of a long-term foothold within the targeted environment. The scope of impact depends on the privileges of the user account and the capabilities of the malicious VSTO add-in. Since Office applications are commonly used, a successful attack could potentially affect a large number of users within an organization.

## Recommendation

*   Deploy the Sigma rule `Potential Persistence Via Visual Studio Tools for Office` to your SIEM to detect suspicious registry modifications related to VSTO add-ins.
*   Monitor registry modifications under the paths `\Software\Microsoft\Office\Outlook\Addins\`, `\Software\Microsoft\Office\Word\Addins\`, `\Software\Microsoft\Office\Excel\Addins\`, `\Software\Microsoft\Office\Powerpoint\Addins\`, and `\Software\Microsoft\VSTO\Security\Inclusion\` (see Sigma rule and references).
*   Implement application control policies to restrict the execution of unsigned or untrusted VSTO add-ins.
*   Regularly review and audit installed Office add-ins to identify and remove any suspicious or unauthorized extensions.
