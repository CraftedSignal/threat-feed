---
brief_id: brief-2026-11-04-rpcping-credential-access
event_id: brief-2026-11-04-rpcping-credential-access
revision: 1
activity_at: "2026-11-04T03:53:59Z"
title: Credential Access via Rpcping.exe
slug: 2026-11-rpcping-credential-access
description: Adversaries can abuse the legitimate Windows utility Rpcping.exe to force NTLM authentication and capture hashes by initiating an RPC connection to a target server.
date: "2026-11-04T03:53:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Rule structure verified against Sigma requirements
tags:
  - credential-access
  - windows
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Detects using Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Rpcping/
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875578(v=ws.11)
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_rpcping_credential_capture.yml
rules:
  - title: Detect Credential Capture via Rpcping.exe
    description: Detects the use of Rpcping.exe with command-line flags intended to force NTLM authentication or utilize named pipes for connectivity testing, indicative of potential credential access attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for Rpcping.exe monitoring
      owner: Detection Engineering
      due: 72h
      evidence: Rule defined in brief
  hunt_leads:
    - lead: Identify historical usage of Rpcping.exe in environment logs
      technique_id: T1003
      data_needed:
        - Process creation events (Event ID 1)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source document indicates Rpcping usage for credential capture
---

Rpcping.exe is a legitimate Windows utility designed for testing RPC connectivity. Adversaries leverage its capability to specify connection protocols and authentication mechanisms to force a target server to initiate an NTLM authentication exchange, potentially leading to NTLM hash capture if intercepted. This technique relies on the -s flag to specify the target server, combined with authentication-specific flags.

## Impact

The primary risk involves the disclosure of NTLM credentials via forced authentication requests. Once NTLM hashes are captured, they may be subject to relay attacks or offline brute-force efforts to recover cleartext passwords.

## Recommendation

Deploy the provided Sigma detection rule to monitor for suspicious command-line execution patterns involving Rpcping.exe. Investigate any instances where Rpcping.exe is executed with -s (server) alongside NTLM authentication flags or named pipe (ncacn_np) transport protocol strings.
