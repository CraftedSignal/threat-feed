---
brief_id: brief-2026-11-11-windows-msix-lpe
event_id: brief-2026-11-11-windows-msix-lpe
revision: 1
activity_at: "2026-11-11T00:38:06Z"
title: 'Microsoft Windows: Local privilege escalation via unsigned MSIX codec (CVE-2026-97799, CVE-2026-116714)'
slug: 2026-11-windows-msix-lpe
description: A public proof-of-concept exploit chain allows local privilege escalation to SYSTEM on Windows by leveraging unsigned MSIX codec packages to execute code within the audiodg.exe process.
date: "2026-11-11T00:38:06Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_26h2:*:*:*:*:*:*:*:*
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Unsigned MSIX codec package allows local privilege escalation to SYSTEM in Windows.
    confidence_band: high
cves:
  - id: CVE-2026-116714
    kev_status: unknown
  - id: CVE-2026-97799
    cvss: 7.8
    epss: 0.00325
    kev_status: "false"
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-97799
  - https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-116714
  - https://sploitus.com/exploit?id=A841C793-655E-53FC-BD5B-799922F7070E
  - https://sploitus.com/exploit?id=A841C793-655E-53FC-BD5B-799922F7070E&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch CVE-2026-97799 and CVE-2026-116714 on all Windows endpoints.
      owner: IT Operations
      due: 24h
      evidence: Microsoft update guide for referenced CVEs.
  hunt_leads:
    - lead: Monitor audiodg.exe for loading unsigned DLLs or modules from non-standard MSIX application directories.
      technique_id: T1068
      data_needed:
        - ImageLoad (Event ID 7) telemetry for audiodg.exe.
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The Windows audio engine (audiodg) loads the attacker DLL.
  mitigation_plan:
    - priority: immediate
      action: Apply Microsoft security updates.
      owner: IT Operations
      addresses: CVE-2026-97799, CVE-2026-116714
      evidence: Source notes that Microsoft update guide carries authoritative detail and affected builds.
---

An exploit chain has been published involving CVE-2026-97799 and CVE-2026-116714. The vulnerability allows an attacker with local access to bypass Windows AppX content checks by deploying a specially crafted, unsigned MSIX codec package. The Windows audio engine process (audiodg.exe) subsequently loads an attacker-supplied DLL. Due to insecure DACL configurations in a Microsoft-shipped service, this facilitates escalation from the LOCAL SERVICE context to SYSTEM.

## Attack Chain
1. Attacker crafts an unsigned MSIX codec package containing a malicious DLL.
2. The package is deployed to the target system.
3. The MSIX package bypasses standard AppX signature and content validation checks.
4. The Windows audio engine process (audiodg.exe) loads the attacker-provided DLL.
5. The DLL executes in the context of the LOCAL SERVICE account.
6. The attacker leverages a service DACL misconfiguration to escalate privileges from LOCAL SERVICE to SYSTEM.

## Recommendation
- Review the Microsoft Security Update Guide for CVE-2026-97799 and CVE-2026-116714 to identify affected Windows builds.
- Apply the relevant security patches for both CVEs immediately to address the service DACL misconfiguration and the MSIX validation bypass.
- Inventory systems with custom codec packages installed via MSIX to identify potential indicators of unauthorized modification.
