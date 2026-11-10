---
brief_id: brief-2026-11-10-curl-ntlm-leak
event_id: brief-2026-11-10-curl-ntlm-leak
revision: 1
activity_at: "2026-11-10T02:49:51Z"
title: 'Curl: NTLM hash leakage via NTLM authentication'
slug: 2026-11-curl-ntlm-leak
description: The Microsoft-shipped version of curl can be abused to leak a user NTLMv2 challenge-response for offline cracking by triggering NTLM authentication with empty credentials.
date: "2026-11-10T02:49:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
affected_os:
  - Windows 10
  - Windows Server 2019
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
    evidence: When no credentials are provided, the Microsoft-shipped curl passes a NULL identity to Windows SSPI, which automatically falls back to the current user's logon session credentials stored in LSASS.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_curl_ntlm_hash_leak_attempt.yml
rules:
  - title: Detect NTLM Hash Leak via Curl
    description: Detects the use of the Microsoft-shipped curl binary with NTLM authentication and empty credentials, which triggers an NTLM handshake using the current user session.
    platform: sigma
    severity: high
    tactics:
      - credential-access
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
    - action: Deploy the provided Sigma rule to catch NTLM hash leakage attempts.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection logic for this specific attack vector.
  hunt_leads:
    - lead: Identify systems frequently invoking curl with empty user flags.
      technique_id: T1187
      data_needed:
        - Process command line arguments
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The specific command line pattern is a clear indicator of the attempted leak.
  mitigation_plan:
    - priority: medium
      action: Identify and refactor any existing automation scripts using insecure curl NTLM calls.
      owner: IT Operations
      addresses: T1187
      evidence: The tool behavior is inherent to the binary implementation.
---

The Microsoft-shipped curl binary (included in Windows 10 and Windows Server 2019 and later) can be leveraged to capture the current user's NTLMv2 challenge-response. When executed with the '--ntlm' flag and an empty user credential specification ('-u :' or '--user :'), the binary passes a NULL identity to the Windows SSPI layer. This triggers a fallback that authenticates using the current user's logon session credentials stored in LSASS without requiring a plaintext password. This artifact can be transmitted to an attacker-controlled listener, facilitating offline cracking or relay attacks.

## Impact

Successful exploitation results in the disclosure of an NTLMv2 hash, which can be cracked offline to recover cleartext credentials or used in relay attacks against other internal network resources.

## Recommendation

* Deploy the detection rule below to identify suspicious curl invocations.
* Audit environment scripts and automation tasks for the use of 'curl --ntlm -u :' or variants, which are likely candidates for abuse.
* Restrict outbound SMB/HTTP authentication attempts from sensitive workstations to untrusted destinations to limit the feasibility of credential relaying.
