---
brief_id: brief-2026-11-10-iis-appcmd-credential-access
event_id: brief-2026-11-10-iis-appcmd-credential-access
revision: 1
activity_at: "2026-11-10T02:51:18Z"
title: Microsoft IIS Service Account Credential Access via AppCmd
slug: 2026-11-iis-appcmd-credential-access
description: Attackers may use the native AppCmd utility to extract sensitive IIS application pool identity credentials from server configuration files.
date: "2026-11-10T02:51:18Z"
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
tags:
  - credential-access
  - iis
  - windows
vendors:
  - Microsoft
products:
  - Internet Information Services (IIS)
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Detects the Internet Information Services (IIS) command-line tool, AppCmd, being used to list passwords
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_iis_appcmd_service_account_password_dumped.yml
  - https://www.netspi.com/blog/technical/network-penetration-testing/decrypting-iis-passwords-to-break-out-of-the-dmz-part-2/
rules:
  - title: Detect Microsoft IIS AppCmd Credential Access
    description: Detects usage of AppCmd.exe to list application pool configuration data that may contain service account passwords.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
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
    - action: Deploy the provided Sigma rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: SigmaHQ/sigma repository source
  hunt_leads:
    - lead: Identify historical usage of appcmd.exe with /config or /xml flags
      technique_id: T1003
      data_needed:
        - Process creation logs (Event ID 1)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source indicates this is a known TTP used for credential dumping
---

Adversaries can leverage the Internet Information Services (IIS) administrative tool, AppCmd.exe, to query application pool configurations. By specifically requesting the output of configuration sections in XML or text format, attackers can reveal sensitive credentials stored in plain text or decryptable formats, facilitating lateral movement or privilege escalation from within a DMZ environment.

## Impact

Successful execution allows an attacker to obtain the service account credentials used by IIS application pools, potentially leading to unauthorized access to linked databases, file shares, or further compromise of the host and internal network.

## Recommendation

- Deploy the provided Sigma rule to monitor for suspicious command-line patterns involving AppCmd.
- Audit existing IIS application pool configurations to ensure they do not store sensitive information that is easily accessible.
- Restrict the use of administrative utilities like AppCmd.exe to authorized system administrators only.
- Implement process monitoring to identify and block unauthorized or anomalous execution of AppCmd.exe.
