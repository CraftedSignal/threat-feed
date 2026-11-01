---
brief_id: brief-2026-11-01-netamloader-windows
event_id: brief-2026-11-01-netamloader-windows
revision: 1
activity_at: "2026-11-01T08:57:47Z"
title: 'NetamLoader: Multi-stage .NET injection malware targeting Windows 10'
slug: 2026-11-netamloader-windows
description: An unidentified threat actor is using a multi-stage .NET assembly-loading framework called NetamLoader to target government-specific Windows 10 builds via AppDomainManager injection and supply chain compromises.
date: "2026-11-01T08:57:47Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Telemetry for CAB file creation in SoftwareDistribution needs environment validation.
tags:
  - netamloader
  - malware
  - supply-chain
  - .net-injection
  - windows-security
vendors:
  - Microsoft
products:
  - Windows 10 China Government Edition
affected_os:
  - Windows 10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: It is suspected the operation involved a supply chain attack, in which bad actors compromised a trusted third-party vendor.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574.002
    technique_name: DLL Side-Loading
    evidence: The sample in question features a ".config" file that employs AppDomainManager injection to load arbitrary .NET assemblies.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    evidence: XAML-2-1 is used to bypass Antimalware Scan Interface (AMSI).
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: enters into a periodic polling loop to fetch an XAML file and execute it in an isolated AppDomain
    confidence_band: high
references:
  - https://thehackernews.com/2026/11/netamloader-malware-targets-government.html
iocs:
  - type: domain
    value: openaigpt4v.com
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block domain openaigpt4v.com at DNS/Web proxy layer.
      owner: SOC
      due: 24h
      evidence: C2 infrastructure identified in the report.
  hunt_leads:
    - lead: Hunt for suspicious CAB archive creation within C:\Windows\SoftwareDistribution\Download\
      technique_id: T1574.002
      data_needed:
        - File creation logs (Sysmon Event ID 11)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'CAB archive containing the .config file was placed in the path: C:\Windows\SoftwareDistribution\Download\'
  mitigation_plan:
    - priority: immediate
      action: Implement application control policies to restrict execution from C:\Windows\SoftwareDistribution\ directories.
      owner: IT Operations
      addresses: NetamLoader persistence and execution
      evidence: Malware stages files into the Windows update cache directories.
---

NetamLoader is a sophisticated, previously undocumented .NET assembly-loading framework identified by Kaspersky. The malware targets custom Windows 10 builds (likely Windows 10 China Government Edition) used by government entities in Asia. It achieves code execution through AppDomainManager injection, hijacking the initialization process of legitimate applications. The malware was observed packaged within Windows cabinet (CAB) archives placed in system update directories, suggesting a potential supply chain compromise of trusted third-party software.

## Attack Chain
1. Delivery of a malicious CAB archive to the victim machine, specifically within 'C:\Windows\SoftwareDistribution\Download\' paths.
2. Extraction of contents into 'C:\Windows\SoftwareDistribution\Download\Install\'.
3. Execution of the legitimate process 'PatchMyPC-ScriptRunner.exe', which parses a malicious 'PatchMyPC-ScriptRunner.exe.config' file.
4. Initiation of AppDomainManager injection to load 'Microsoft.HostIntegration.Connectors.dll'.
5. Parsing of 'fabric.config' by the DLL to load the 'Resources.resx' file containing encoded and encrypted payloads.
6. Multi-stage decryption and loading of XAML and .NET modules, including XAML-2-1 for AMSI bypass.
7. Execution of XAML-3 within 'dllhost.exe' and final loading of the .NET 2 Plugin.
8. Deployment of a periodic C2 polling loop to 'openaigpt4v.com' for further payload retrieval and execution in isolated AppDomains.

## Recommendation
- Inventory systems containing Windows 10 China Government Edition or specialized government Windows builds.
- Monitor directory paths 'C:\Windows\SoftwareDistribution\Download\' for the presence of unexpected CAB archives or unauthorized file extractions into 'Install' subdirectories.
- Implement strict process execution policies for 'PatchMyPC-ScriptRunner.exe' and ensure hashes match known legitimate versions from the vendor.
- Block communication with 'openaigpt4v.com' at the network perimeter.
- Audit .NET configuration files (.config) in sensitive directories for unexpected 'AppDomainManager' settings.
