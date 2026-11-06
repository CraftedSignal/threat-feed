---
brief_id: brief-2026-11-06-external-smb-login
event_id: brief-2026-11-06-external-smb-login
revision: 1
activity_at: "2026-11-06T22:59:37Z"
title: Detection of external remote SMB logon activity
slug: 2026-11-external-smb-login
description: Successful remote SMB authentication originating from external, non-private IP addresses can indicate exposed services and potential credential exploitation.
date: "2026-11-06T22:59:37Z"
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
  validation_status: Rule structure verified against provided source schema.
tags:
  - windows
  - smb
  - authentication
  - perimeter-security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Successful logon from public IP address via SMB. This can indicate a publicly-exposed SMB port.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Exposure of SMB via public IP often facilitates brute-force or credential stuffing attempts.
    confidence_band: med
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_successful_external_remote_smb_login.yml
rules:
  - title: Detect Successful External Remote SMB Logon
    description: Detects successful remote SMB authentication (Logon Type 3) originating from non-RFC1918 (public) IP addresses, indicating potential exposure of the SMB service.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1133
    data_sources:
      - security
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review perimeter firewall configurations to identify exposed SMB (TCP 445) ports.
      owner: IT Operations
      due: 24h
      evidence: Source notes that public IP logons indicate publicly exposed SMB ports.
  hunt_leads:
    - lead: Identify historical 4624 events from non-RFC1918 IPs
      technique_id: T1133
      data_needed:
        - Windows Event Log 4624
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Log data allows retrospective analysis of unauthorized access attempts.
  mitigation_plan:
    - priority: immediate
      action: Block TCP 445 on internet-facing interfaces.
      owner: IT Operations
      addresses: SMB port exposure
      evidence: Source identifies public IP SMB logons as a risk indicator.
---

This brief addresses the detection of successful remote SMB (Logon Type 3) authentication sessions where the source IP address is classified as a public IP. Such activity suggests that the SMB service is exposed to the internet, creating a significant risk for brute-force attacks, credential stuffing, or unauthorized remote file access.

## Recommendation

* Deploy the Sigma rule below to monitor for successful external SMB logons in Windows Security event logs.
* Audit edge firewalls to ensure TCP port 445 is not exposed to the public internet.
* Implement restrictive network ACLs or VPN requirements for any service requiring SMB access.
* Review authentication logs for accounts consistently triggering these alerts to identify potentially compromised credentials.
