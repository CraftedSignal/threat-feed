---
title: Defendnot HackTool Installation via PowerShell
slug: 2026-10-defendnot-installation
description: The Defendnot hacktool is deployed via PowerShell one-liners to disable Windows Defender by registering a malicious, fake antivirus product through undocumented WSC APIs.
date: "2026-10-19T08:54:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-impairment
  - powershell
  - windows-security
  - hacktool
rules:
  - title: Detect Defendnot HackTool Installation via PowerShell
    description: Detects execution of Defendnot installation via PowerShell one-liner that downloads and executes the script from remote URLs.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM/EDR.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific command line patterns.
  hunt_leads:
    - lead: Search PowerShell Script Block (Event 4104) logs for remote connection attempts to dnot.sh.
      technique_id: T1685
      data_needed:
        - ScriptBlockText
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: README specifically references this as the installation vector.
---

Defendnot is a post-exploitation hacktool designed to facilitate defense impairment on Windows systems. It operates by abusing undocumented Windows Security Center (WSC) APIs to register a malicious, fake antivirus product. By successfully registering this fake product, the tool forces the Windows Security Center to recognize it as a legitimate security solution, which subsequently triggers the automatic disabling of Windows Defender. This technique allows attackers to eliminate real-time endpoint protection without triggering standard alerts associated with modifying registry keys or services directly. The tool is typically delivered and executed through PowerShell one-liners that fetch remote scripts from URLs hosted on GitHub or specific download domains. Its primary objective is to create a stealthy window of opportunity for further malicious activities by silencing the operating system's native security mechanisms.

## Attack Chain

1. An attacker gains initial access to the target Windows workstation or server.
2. The attacker executes a PowerShell one-liner command to fetch the Defendnot script.
3. The script is downloaded from a remote location, such as a GitHub repository or a specific hosting domain.
4. PowerShell executes the downloaded script block directly in memory.
5. The script invokes undocumented WSC APIs (Windows Security Center) via PowerShell or injected reflective assembly.
6. The tool registers itself as a security provider in the Windows Security Center repository.
7. The Windows Security Center (WSC) detects the new provider and automatically disables Windows Defender to prevent conflicts.
8. The attacker achieves their objective of neutralizing endpoint security to perform further exploitation.

## Impact

Defendnot creates a critical security gap by disabling Windows Defender, the primary defense layer on Windows systems. If successful, this attack leaves the affected host completely exposed to additional malicious payloads, exfiltration, or lateral movement, as the endpoint can no longer perform real-time monitoring or threat blocking. This tool targets Windows environments where Windows Defender is the primary or sole security solution.

## Recommendation

* Deploy the Sigma rules provided in this brief to detect the execution of PowerShell scripts containing indicators related to Defendnot distribution.
* Monitor PowerShell Script Block Logging (Event ID 4104) for the inclusion of known download URLs ('dnot.sh') or common GitHub paths used by the tool.
* Restrict the ability for unauthorized users or processes to invoke WSC APIs or modify Windows Security Center provider registrations through Group Policy or EDR policies.
