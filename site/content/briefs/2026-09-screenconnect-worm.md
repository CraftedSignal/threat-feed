---
title: Worm-like Campaign Leveraging Modified ScreenConnect Clients
slug: 2026-09-screenconnect-worm
description: Threat actors are using social engineering to deploy modified, backdoored ScreenConnect clients that automate multi-stage payload execution and self-propagation across connected remote hosts.
date: "2026-09-07T11:55:13Z"
lastmod: "2026-09-12T00:50:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*
tags:
  - remote-access
  - worm
  - lateral-movement
vendors:
  - ConnectWise
products:
  - ScreenConnect
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: The attacks ... start with the rogue clients being deployed on victims’ machines via social engineering.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.005
    technique_name: Visual Basic
    evidence: The malicious ScreenConnect instances have been observed spawning repeated Windows Script Host (wscript.exe) child processes to deploy four VBScript files.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: the attackers created a User Run Key pointing to another VBScript file, for persistence.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.002
    technique_name: Bypass User Account Control
    evidence: erases staging evidence, attempts UAC bypass, and installs and conceals a ScreenConnect client
    confidence_band: high
cves:
  - id: CVE-2026-84869
    cvss: 9.9
    epss: 0.00382
references:
  - https://www.securityweek.com/modified-screenconnect-clients-used-in-worm-like-campaign/
  - https://www.cve.org/CVERecord?id=CVE-2026-84869
rules:
  - title: Detect Suspicious wscript.exe Activity from ScreenConnect
    description: Detects wscript.exe spawning from ScreenConnect temporary directories, a behavior associated with the reported worm-like campaign.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable file transfer functionality in all ScreenConnect instances.
      owner: IT Operations
      due: 24h
      evidence: ConnectWise recommends that administrators disable the file transfer functionality in ScreenConnect to reduce the risk.
  hunt_leads:
    - lead: Search for wscript.exe processes spawned by ScreenConnect binaries.
      technique_id: T1059.005
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The malicious ScreenConnect instances have been observed spawning repeated Windows Script Host (wscript.exe) child processes
  mitigation_plan:
    - priority: immediate
      action: Disable file transfer feature.
      owner: IT Operations
      addresses: ScreenConnect
      evidence: ConnectWise suggests admins apply extra scrutiny to any on-premises ScreenConnect installations.
updates:
  - at: "2026-09-12T00:50:00Z"
    level: L2
    summary: added CVE-2026-84869
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-84869
---

Since late August 2026, threat actors have been executing a worm-like campaign involving rogue, backdoored ScreenConnect client instances. The attack typically begins with social engineering, where victims are tricked into installing malicious software under the guise of technical support. Once the rogue ScreenConnect instance is active, it immediately initiates a multi-stage execution chain using Windows Script Host to launch VBScript files from the ScreenConnect temporary directory. 

The malicious activity includes system reconnaissance, payload staging, and the execution of PowerShell scripts for UAC bypass and persistent concealment. Crucially, the malware is designed to propagate by continuously monitoring for new host connections and infecting them with the same four-stage VBScript chain. ConnectWise has acknowledged an issue affecting file transfer behavior in ScreenConnect and is working on a fix; they currently advise administrators to disable file transfer functionality to mitigate the risk of unauthorized payload delivery.

## Attack Chain

1. Initial access is gained via social engineering (e.g., tech support impersonation) leading the victim to install a rogue or backdoored ScreenConnect client.
2. The rogue ScreenConnect client executes four VBScript files directly from its temporary directory using wscript.exe.
3. The VBScript files perform local system reconnaissance and stage secondary payloads.
4. The malware establishes persistence by creating a User Run Key registry entry pointing to a malicious VBScript file.
5. A PowerShell script is executed to perform UAC bypass and finalize the installation of a concealed ScreenConnect client.
6. The concealed ScreenConnect client continuously monitors for new remote host connections.
7. Upon identifying new host connections, the client propagates the four-stage VBScript chain to the new endpoint, enabling worm-like lateral movement.

## Impact

The campaign facilitates unauthorized access, persistent surveillance, and potential lateral movement across organizations using ConnectWise ScreenConnect. By leveraging existing remote support infrastructure to spread malicious payloads, attackers can compromise multiple endpoints within a network simultaneously. If the attack succeeds, the adversary gains full remote control over the affected machines, facilitating data exfiltration, further reconnaissance, or the deployment of additional malicious tools.

## Recommendation

Prioritize the following actions to protect your environment:
- Immediately disable the file transfer functionality in all on-premises and cloud-based ScreenConnect instances as recommended by ConnectWise.
- Implement strict endpoint monitoring for wscript.exe spawned from ScreenConnect-related directories.
- Audit all user-level Run Key registry entries for suspicious scripts or unrecognized binaries.
- Monitor for unauthorized ScreenConnect client installations that lack proper management approval.
- Review network logs for unusual outbound connections originating from ScreenConnect processes.
