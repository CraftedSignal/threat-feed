---
title: Detection of Forced Authentication via SMB Named Pipes
slug: 2026-09-forced-authentication-smb
description: Adversaries leverage Linux-based systems to coerce Windows hosts into authenticating against attacker-controlled resources via SMB named pipes, facilitating NTLM hash capture and SMB relay attacks.
date: "2026-09-19T01:05:48Z"
lastmod: "2026-09-19T13:09:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - active-directory
  - smb
  - linux
  - windows
  - coercion
vendors:
  - Microsoft
products:
  - Active Directory
  - Windows
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
    evidence: Adversaries exploit these by forcing authentication from a Linux host to capture credentials or perform relay attacks.
    confidence_band: high
references:
  - https://github.com/p0dalirius/windows-coerced-authentication-methods
  - https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications
  - https://attack.mitre.org/techniques/T1187/
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_forced_authentication_pipes.toml
rules:
  - title: Detect Forced Authentication via SMB Named Pipes
    description: Detects suspicious SMB connection attempts from Linux hosts targeting sensitive Windows RPC named pipes indicative of coerced authentication.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1187
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
    - action: Enable 'Audit Detailed File Share' audit policy on all Windows endpoints
      owner: IT Operations
      due: 72h
      evidence: Source documentation specifies audit policy requirements.
  hunt_leads:
    - lead: SMB connections from non-standard Linux hosts to Domain Controllers
      technique_id: T1187
      data_needed:
        - Network logs and Windows 5145 events
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The detection logic highlights Linux-to-Windows SMB coercion.
  mitigation_plan:
    - priority: immediate
      action: Enable SMB Signing and LDAP channel binding
      owner: IT Operations
      addresses: Coerced authentication relay attacks
      evidence: Standard security posture to mitigate NTLM relay.
updates:
  - at: "2026-09-19T13:09:37Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_forced_authentication_pipes.toml
---

This threat involves the abuse of Remote Procedure Call (RPC) interfaces over SMB to force Active Directory-joined Windows hosts to authenticate to an attacker-controlled system. By initiating SMB connections from a Linux host to sensitive Windows named pipes - such as Spoolss, lsarpc, efsrpc, or samr - an attacker can trigger an authentication request. If successful, this process allows the attacker to intercept NTLM hashes for offline cracking or to perform SMB relay attacks to escalate privileges or move laterally. This technique is a well-documented method for credential access and network-based movement within an environment. Defenders must monitor cross-platform SMB traffic patterns and ensure that Windows environments are hardened against coerced authentication, particularly where Linux-based systems interact with critical AD infrastructure.

## Attack Chain

1. The attacker gains initial access to a Linux host within the enterprise network.
2. The attacker identifies an Active Directory-joined Windows host (e.g., Domain Controller or high-value server) accessible over port 445.
3. The attacker initiates an SMB connection from the compromised Linux host to the target Windows system.
4. The attacker makes an RPC request to a vulnerable named pipe on the target, such as \pipe\spoolss or \pipe\efsrpc, to trigger authentication.
5. The target Windows system attempts to authenticate to the attacker's Linux host to fulfill the RPC request.
6. The attacker captures the resulting NTLM authentication challenge/response on the Linux host.
7. The attacker performs offline cracking of the captured NTLM hash or uses the authentication attempt to relay the credentials to other services within the network.

## Impact

Successful exploitation allows attackers to obtain valid user or machine credentials, which can be used to escalate privileges, compromise domain accounts, or move laterally throughout the Active Directory environment. The scope of impact typically includes the compromise of sensitive administrative accounts if relay attacks against critical infrastructure are successful.

## Recommendation

1. Enable 'Audit Detailed File Share' (Success and Failure) on all Windows hosts to ensure Event ID 5145 is generated when named pipes are accessed.
2. Deploy the provided Sigma rule to monitor for suspicious SMB connection attempts from Linux hosts paired with specific RPC named pipe access on Windows targets.
3. Implement network segmentation to restrict SMB traffic between Linux hosts and sensitive Windows domain infrastructure.
4. Review and harden systems against NTLM relay attacks by enabling SMB Signing and LDAP Channel Binding where applicable.
