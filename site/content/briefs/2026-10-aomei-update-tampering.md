---
title: UNC7017 Supply Chain Attack via AOMEI Backupper Update Infrastructure
slug: 2026-10-aomei-update-tampering
description: UNC7017 performed an opportunistic supply chain attack by intermittently compromising AOMEI update servers to deliver backdoors, credential-harvesting pop-ups, and remote administration tools to Windows users.
date: "2026-10-16T18:27:42Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UNC7017
tags:
  - supply-chain
  - backdoor
  - remote-access
  - credential-harvesting
vendors:
  - AOMEI Technology
products:
  - AOMEI Backupper
  - AnyViewer
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: The attacker performed a supply chain attack by tampering with AOMEI update files.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The implants provided a remote shell and could fetch and run new code on command.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: The downloader unpacked a bundle into a local Radmin folder, created a scheduled task set to run every three hours.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Rendering that pop-up can make Windows send the logged-in user's NetNTLMv2 authentication response.
    confidence_band: high
references:
  - https://thehackernews.com/2026/10/attackers-tampered-with-aomei.html
iocs:
  - type: domain
    value: storage-data.com
  - type: domain
    value: promotion.storage-data.com
  - type: domain
    value: aomei.storage-data.com
  - type: ip
    value: 8.210.84.56
  - type: ip
    value: 8.218.65.184
  - type: ip
    value: 47.239.60.117
ioc_counts:
  domain: 3
  ip: 3
rules:
  - title: Detect AOMEI Backupper Child Process Execution
    description: Detects potentially malicious processes spawned by the AOMEI Backupper update service or associated GUI components, often indicative of the CROSSROAD downloader activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
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
    - action: Block listed C2 domains and IPs at the edge firewall/proxy.
      owner: SOC
      due: 24h
      evidence: Source provided specific malicious indicators.
    - action: Hunt for scheduled tasks named RadminComponentRuntime or NitroRuntime.
      owner: SOC
      due: 24h
      evidence: Observed persistence mechanism used by the backdoor.
  hunt_leads:
    - lead: Search for unknown processes spawned by Backupper.exe or related AOMEI services.
      technique_id: T1059
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The downloader runs with the privileges of the AOMEI process that launched it.
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound SMB and WebDAV to internet-facing addresses.
      owner: IT Operations
      addresses: All enterprise workstations.
      evidence: Mitigates the non-executable NTLM credential harvesting technique.
---

Between May and July 2026, the threat actor UNC7017 conducted a sophisticated, short-lived supply chain attack against AOMEI Technology. By gaining unauthorized access to AOMEI update servers, the attackers repeatedly replaced configuration files (down_html.ini and Notifycfg.ini) for short windows of 5-10 minutes. Because the AOMEI Backupper software lacks cryptographic verification for these update files, compromised clients automatically downloaded and executed malicious payloads delivered via the update flow.

The campaign avoided detection by reverting the server-side configuration to legitimate files immediately after the malicious windows, ensuring that triage attempts checking the vendor's site would appear clean. The attack targets included organizations in IT services, telecommunications, and education across 11 countries. The campaign notably utilized both binary implants and a non-executable WebDAV-based NTLM credential harvesting technique. AOMEI has reported taking corrective server-side actions, but no software update has been released to address the lack of cryptographic verification in the update mechanism itself.

## Attack Chain

1. Attacker gains unauthorized write access to AOMEI update server infrastructure.
2. Attacker replaces 'down_html.ini' and 'Notifycfg.ini' with malicious variants for a 5-10 minute window.
3. Target AOMEI Backupper process checks for updates over HTTPS and downloads the attacker-specified malicious package.
4. 'Notifycfg.ini' triggers the execution of the downloaded malicious package with the privileges of the AOMEI service.
5. The 'CROSSROAD' downloader executes, creates a scheduled task for persistence, and removes itself from the disk.
6. The scheduled task invokes a signed, legitimate Radmin binary paired with a malicious DLL that loads the 'SHINYROAD' backdoor.
7. 'SHINYROAD' establishes C2 communication; attackers may subsequently push the Adaptix framework disguised as Nitro PDF software.
8. In some instances, the attacker triggers an invisible WebDAV pop-up to force NTLMv2 authentication credential leakage.

## Impact

The campaign successfully compromised systems across 11 countries, including Australia, Brazil, India, Pakistan, Portugal, Singapore, South Africa, Spain, Switzerland, Türkiye, and the United States. Successfully infected machines grant the actor remote shell access, persistence, and potential credential harvesting capabilities. As the implant runs with the privileges of the AOMEI service, it can facilitate system-wide software installation and code execution, representing a significant compromise of the host environment.

## Recommendation

* Hunt for unauthorized scheduled tasks including 'RadminComponentRuntime' or 'NitroRuntime' created between May and July 2026.
* Block outbound connections to the malicious infrastructure (storage-data[.]com, promotion.storage-data[.]com, aomei.storage-data[.]com) and the associated IP addresses (8.210.84.56, 8.218.65.184, 47.239.60.117).
* Block outbound SMB (TCP 445) and WebDAV traffic from internal hosts to unauthorized external destinations to prevent NTLM credential relay.
* Inspect file system logs for unsigned executables or suspicious binaries originating from AOMEI's local application data folders.
* Deploy Sigma rules to detect the creation of unusual scheduled tasks from AOMEI-related processes.
