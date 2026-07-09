---
title: CitrixBleed 2 (CVE-2025-5777) Exploitation Leading to Dragonforce Ransomware
slug: 2026-07-citrixbleed2-dragonforce
description: Initial Access Brokers are actively exploiting CitrixBleed 2 (CVE-2025-5777) on NetScaler appliances to steal session tokens, achieve local privilege escalation, establish persistence via legitimate remote access tools, and ultimately deploy Dragonforce ransomware.
date: "2026-07-09T20:25:12Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:fips:*:*:*
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:ndcpp:*:*:*
  - cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:-:*:*:*
  - cpe:2.3:a:citrix:netscaler_gateway:*:*:*:*:*:*:*:*
tags:
  - ransomware
  - initial-access
  - privilege-escalation
  - persistence
  - citrix
  - netscaler
  - dragonforce
vendors:
  - Citrix
products:
  - NetScaler
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The intrusions began with exploitation of CitrixBleed 2 (CVE-2025-5777), where malformed pre-auth login requests leaked NetScaler memory.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: attackers to steal and replay valid session tokens, making MFA effectively irrelevant once a live session was hijacked.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: escalate to SYSTEM through a registry-symlink/AppMgmt privilege-escalation trick
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: create rogue local admin accounts
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: establish persistence with legitimate remote access tools like ScreenConnect and Zoho Assist.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: establish persistence with legitimate remote access tools like ScreenConnect and Zoho Assist.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1074
    technique_name: Data Staged
    evidence: asas.zip, ex.zip, *_update.zip Password-protected archives from temp[.]sh
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: relay.dltsolutions[.]top ScreenConnect Relay, opa[.]tlsd[.]shop Netbird Relay
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: the operation ended with DragonForce ransomware deployment
    confidence_band: high
cves:
  - id: CVE-2025-5777
    cvss: 7.5
    epss: 0.99897
references:
  - https://www.huntress.com/blog/citrixbleed-2-dragonforce-ransomware
iocs:
  - type: hash_sha256
    value: c84739655ce1af0a0269138263d47567418f69e0f75e249f8e23bc21802209e2
  - type: hash_sha256
    value: eb083365dc70d0294e8c4f55a2e78be0edb0f3497f2a06a70c9f474dafab48d8
  - type: hash_sha256
    value: c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d
  - type: domain
    value: relay.dltsolutions[.]top
  - type: domain
    value: relay.eurofin[.]digital
  - type: domain
    value: vpts[.]us
  - type: domain
    value: opa[.]tlsd[.]shop
ioc_counts:
  domain: 4
  hash_sha256: 3
rules:
  - title: Detect Suspicious AppMgmt Service Interaction for LPE
    description: Detects command line patterns indicative of the registry-symlink/AppMgmt privilege escalation trick used by attackers to gain SYSTEM privileges. This includes starting the AppMgmt service and forcing group policy updates, often seen together in LPE chains.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1548.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Local Administrator Account Creation
    description: Detects the creation of specific local administrator accounts (`ctxsvc`, `CtxAppVCOMService`, `test`) identified as adversary accounts in Dragonforce ransomware attacks following CitrixBleed 2 exploitation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1136.001
    data_sources:
      - security
      - windows
  - title: Detect Installation of Legitimate Remote Access Software by MSI
    description: Detects process creation events for msiexec installing known legitimate remote access tools (ScreenConnect, Zoho Assist) with specific installer file names identified in Dragonforce ransomware attacks. This can indicate unauthorized persistence.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - persistence
    techniques:
      - T1059.003
      - T1133
    data_sources:
      - process_creation
      - windows
  - title: Detect Dragonforce Ransomware Execution (1.exe)
    description: Detects the execution of the Dragonforce ransomware payload named '1.exe' with a specific SHA256 hash observed in attacks following CitrixBleed 2 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - process_creation
      - windows
rules_count: 4
---

Huntress has observed a coordinated campaign across the first half of 2026 where Initial Access Brokers (IABs) are exploiting CVE-2025-5777, dubbed "CitrixBleed 2", on Citrix NetScaler appliances. This critical vulnerability allows attackers to leak NetScaler memory via malformed pre-authentication login requests, enabling the theft and replay of valid session tokens to bypass multi-factor authentication. Once initial access is gained, the attackers employ a standardized playbook involving novel local privilege escalation techniques, such as a registry-symlink/AppMgmt trick, to obtain SYSTEM privileges. They then establish persistence by creating rogue local administrator accounts and installing legitimate remote access tools like ScreenConnect and Zoho Assist. The final stage of these intrusions is the deployment of Dragonforce ransomware, encrypting victim data for impact.

## Attack Chain

1. **Initial Access**: Attackers exploit CVE-2025-5777 (CitrixBleed 2) on exposed NetScaler appliances by sending malformed pre-authentication login requests, causing memory leakage and the theft of valid session tokens.
2. **Authentication Bypass**: Stolen valid session tokens are replayed to hijack active user sessions, effectively bypassing multi-factor authentication and gaining authenticated access to the target environment.
3. **Privilege Escalation**: SYSTEM-level privileges are achieved using a "registry-symlink/AppMgmt trick", likely executed via command line instructions such as `cmd.exe /c sc start AppMgmt >nul 2>nul` and `cmd.exe /c gpupdate /force >nul 2>nul`, and leveraging LPE tooling like `eng.exe` or `legal.exe`.
4. **Defense Evasion & Persistence**: Rogue local administrator accounts, including `ctxsvc`, `CtxAppVCOMService`, and `test`, are created to maintain access and evade detection.
5. **Persistence & Command and Control**: Legitimate remote access tools like ScreenConnect (`Us.msi`, `SC.msi`) and Zoho Assist (`za.msi`) are installed to establish persistent remote access and maintain C2 communications via relays such as `relay.dltsolutions[.]top`.
6. **Collection & Staging**: Attackers create password-protected archives (e.g., `asas.zip`, `ex.zip`) and upload them to temporary file hosting services like `temp[.]sh`, likely for data staging prior to exfiltration.
7. **Impact**: Dragonforce ransomware (`1.exe`) is executed, encrypting files on compromised systems, leading to significant disruption and data loss.

## Impact

In the first half of 2026, Huntress observed a half-dozen strikingly similar intrusions across unrelated organizations that followed this seven-step attack chain, culminating in Dragonforce ransomware deployment. This indicates a highly standardized and effective operational playbook by Initial Access Brokers. Successful compromise results in complete system takeover, potential data exfiltration, and the encryption of critical business data, leading to severe operational disruption, financial loss from ransom payments, and potential reputational damage. The ability to bypass MFA renders traditional access controls ineffective once the initial vulnerability is exploited.

## Recommendation

* Immediately patch all exposed Citrix NetScaler appliances against CVE-2025-5777 to prevent initial access.
* Implement detections for the execution of suspicious LPE commands like `cmd.exe /c sc start AppMgmt >nul 2>nul` and `cmd.exe /c gpupdate /force >nul 2>nul` by deploying the "Detect Suspicious AppMgmt Service Interaction for LPE" Sigma rule.
* Monitor for the creation of new local administrator accounts with unusual names such as `ctxsvc`, `CtxAppVCOMService`, or `test` using the "Detect Suspicious Local Administrator Account Creation" Sigma rule.
* Block inbound and outbound connections to the C2 domains `relay.dltsolutions[.]top`, `relay.eurofin[.]digital`, `vpts[.]us`, and `opa[.]tlsd[.]shop` at your network perimeter.
* Deploy the "Detect Installation of Legitimate Remote Access Software by MSI" Sigma rule to identify unauthorized deployments of ScreenConnect or Zoho Assist.
* Scan endpoints for the Dragonforce ransomware hash `c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d` and block execution.
* Review and terminate all outstanding user sessions on NetScaler appliances and conduct an audit for any suspicious accounts or remote management tooling not authorized by your organization.
