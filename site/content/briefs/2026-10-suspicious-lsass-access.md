---
title: Suspicious LSASS Process Access Monitoring
slug: 2026-10-suspicious-lsass-access
description: Detection of unauthorized handles to the Local Security Authority Subsystem Service (LSASS) process to identify potential credential dumping attempts on Windows systems.
date: "2026-10-05T12:01:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - windows
  - lsass
  - sysmon
vendors:
  - Microsoft
  - Cisco
  - Oracle
products:
  - Windows
  - Cisco Secure Client
  - Cisco AnyConnect Secure Mobility Client
  - Oracle Database
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Identifies access attempts to LSASS handle, this may indicate an attempt to dump credentials from Lsass memory.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_suspicious_lsass_access_generic.toml
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md
rules:
  - title: Suspicious LSASS Process Access
    description: Detects unauthorized handle requests to LSASS process, potentially indicating credential dumping attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
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
    - action: Enable Sysmon Event ID 10 across all Windows endpoints
      owner: IT Operations
      due: 72h
      evidence: Setup instructions provided in brief
    - action: Deploy detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief
  hunt_leads:
    - lead: Identify processes with unusual access rights to LSASS not covered by exclusion list
      technique_id: T1003.001
      data_needed:
        - Sysmon Event ID 10
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: High frequency of credential dumping via LSASS targeting
  mitigation_plan:
    - priority: short_term
      action: Enable Credential Guard to protect LSASS memory
      owner: IT Operations
      addresses: Credential dumping
      evidence: Standard security hardening guidance for LSASS
---

The Local Security Authority Subsystem Service (LSASS) is a critical Windows process responsible for security policy enforcement and user authentication. Because it maintains sensitive credential material in memory, it is a primary target for adversaries seeking to escalate privileges or move laterally. This detection approach focuses on identifying unauthorized handle requests to LSASS.exe, which is a hallmark of credential dumping tools (such as those mapped to MITRE ATT&CK T1003.001). 

Defenders must distinguish between malicious access and legitimate operations performed by security software, system management tools, and administrative utilities. The detection logic provides an exclusion list for common benign processes like Windows Defender, system management agents (Cisco, Oracle), and security tools (Process Explorer). Monitoring LSASS handle access provides high-value visibility into potential post-compromise credential harvesting activities.

## Impact

Successful exploitation of LSASS memory allows adversaries to extract cleartext passwords, NTLM hashes, and Kerberos tickets. This compromise can lead to full administrative account takeover, facilitating lateral movement across the network and persistent, unauthorized access to sensitive corporate resources.

## Recommendation

* Enable Sysmon Event ID 10 (ProcessAccess) logging across all Windows endpoints to capture handle requests to LSASS.
* Deploy the provided Sigma rule to detect unauthorized process access to LSASS.
* Review the exclusion list periodically to ensure that enterprise-specific management software and legitimate security tools are not triggering false positives.
* Use the triage guidance provided: investigate the ParentImage, GrantedAccess bits, and CallTrace in the event to differentiate between administrative automation and malicious activity.
* Isolate endpoints where unauthorized LSASS dumping is confirmed and rotate credentials for compromised administrative accounts immediately.
