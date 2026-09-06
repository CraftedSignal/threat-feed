---
title: REVSTEALER Modular Information Stealer and Persistence Modules
slug: 2026-09-revstealer-modules
description: REVSTEALER is an emerging information stealer that drops modular components capable of persistence, credential theft, clipboard hijacking, and stealthy cryptocurrency mining while disabling security controls.
date: "2026-09-06T10:42:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - infostealer
  - crypto-miner
  - persistence
  - malware
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1218.003
    technique_name: CMSTP
    evidence: To gain administrator rights, it abuses the Windows CMSTP tool, falling back to a standard elevation prompt if that fails.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    evidence: It adds Microsoft Defender exclusions for common folders and file types, disables 5 Windows Update services.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: Runs a cryptocurrency miner with administrator rights.
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/four-revstealer-linked-modules-disable.html
iocs:
  - type: hash_sha256
    value: adc4aa652965396b52e79435ca54987ae9eb21bf5e67de5e9461b09655165ee4
  - type: hash_sha256
    value: 13d7237d7289e67c2d806a65d52580b453ce4987acbe2c4c4d04833f55ebccfa
  - type: hash_sha256
    value: 7c08cf409194056a8517865e5d3433d1499bb8262263b55b49b8b07d9d182fcb
  - type: hash_sha256
    value: 14b2ac356ed75d10ef40bbaaa48e7dd9fff7de9719c2a43ad123fe843dd4e4e2
  - type: hash_sha256
    value: c66d2b77b9e85c53391891212413ad9a99eb66f4b11c6a431e78884a5b2651e5
  - type: domain
    value: monitor5.roast-core85.click
  - type: domain
    value: config.hubdisplay.lol
  - type: domain
    value: health.journal-metric.lol
  - type: domain
    value: metric.gardenpark.click
ioc_counts:
  domain: 4
  hash_sha256: 5
rules:
  - title: Detect CMSTP Execution for Privilege Escalation
    description: Detects the use of the Connection Manager Profile Installer (cmstp.exe) to execute remote script files, a common technique for bypass/elevation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1218.003
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
    - action: Block identified C2 domains at DNS resolver
      owner: SOC
      due: 24h
    - action: Deploy Sigma rule for CMSTP execution
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for unknown processes executing out of user profile directories
      technique_id: T1547.001
      data_needed:
        - Process creation logs with full path
      priority: high
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: Remove unauthorized Microsoft Defender exclusions
      owner: IT Operations
      addresses: LockAppHost modules
---

REVSTEALER is a commercial information stealer detected in the wild since February 2026, primarily distributed via malicious game-cheat lures and impersonated AI applications. While the core stealer exfiltrates credentials, browser data, and wallet files before self-deleting, it is often associated with four post-exploitation modules: ProManager, WinUpdate, SoftManager, and LockAppHost. These modules persist in the user profile to perform secondary malicious actions. 

Most notably, LockAppHost achieves administrative persistence by abusing the CMSTP tool to disable Windows Update services and Microsoft Defender features. It subsequently deploys a cryptocurrency miner masked within system processes. These modules share tradecraft with the core stealer, including indirect system calls, packer-based obfuscation, and the use of Polygon smart contracts for resilient command-and-control communication. Organizations should prioritize detection of these persistent modules, as the primary stealer may have already completed its execution before security teams identify the compromise.

## Attack Chain

1. Initial delivery of REVSTEALER via malicious game-cheat lures or impersonated software installers.
2. Execution of the core stealer using indirect syscalls and anti-sandbox checks to evade security analysis.
3. Exfiltration of credentials, cookies, and sensitive session data to the primary C2 or blockchain-based backup.
4. Deployment of persistent secondary modules (e.g., LockAppHost) into the user profile.
5. Elevation of privileges using CMSTP abuse to gain administrative rights.
6. Disabling of Windows Update services and modification of Microsoft Defender exclusions to weaken system defenses.
7. Execution of a hidden cryptocurrency miner within a suspended instance of legitimate processes like nslookup.exe or svchost.exe.
8. Long-term persistence maintained via Registry Run keys or scheduled tasks for secondary modules.

## Impact

Successful infection results in the total loss of credentials, browser cookies, cryptocurrency wallet contents, and messaging data. The persistence modules enable long-term resource hijacking through cryptocurrency mining and proxying, while the weakened security state leaves the machine susceptible to subsequent opportunistic exploitation. Observed activity includes thousands of samples detected in the wild, indicating high-volume distribution targeting end users.

## Recommendation

1. Deploy Sigma rules to monitor for unauthorized execution of cmstp.exe for privilege escalation.
2. Hunt for persistence artifacts associated with the identified modules, specifically Registry Run keys and scheduled tasks that execute unsigned binaries in user profile directories.
3. Monitor for Windows Update service status changes or unusual Defender exclusion modifications.
4. Inspect suspended processes (nslookup.exe, svchost.exe) for unexpected malicious threads or memory-resident payloads consistent with crypto-mining.
5. Require password resets and session revocation for any accounts identified on compromised machines due to the theft of session cookies and browser secrets.
