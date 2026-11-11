---
brief_id: brief-2026-11-11-citrus-ransomware
event_id: brief-2026-11-11-citrus-ransomware
revision: 1
activity_at: "2026-11-11T10:50:22Z"
title: 'Citrus Ransomware: Contractor exploitation and LLM-assisted post-exploitation'
slug: 2026-11-citrus-ransomware
description: Citrus Ransomware leverages compromised contractor credentials, VLESS tunnels, and LLM-generated scripts to escalate privileges and deploy ransomware, notably exploiting CVE-2026-54121 (Certighost).
date: "2026-11-11T10:50:22Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
tags:
  - ransomware
  - initial-access
  - privilege-escalation
  - windows
  - active-directory
vendors:
  - Microsoft
  - 1C
products:
  - Active Directory Certificate Services
  - 1C:Enterprise
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The attackers gain initial access to victims infrastructure through compromised contractors.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: The attackers run commands on compromised systems through the standard Windows command interpreter and PowerShell.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: To do this, they attempted to exploit the authentication bypass vulnerability CVE-2026-54121 (Certighost).
    confidence_band: high
cves:
  - id: CVE-2026-54121
    cvss: 8.8
    epss: 0.01836
    kev_status: "false"
references:
  - https://securelist.com/citrus-ransomware/121879/
  - https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/detecting-cve-2026-54121-certighost-with-microsoft-defender/4542861
iocs:
  - type: ip
    value: 91.210.109.118
ioc_counts:
  ip: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block IP 91.210.109.118 at perimeter firewalls
      owner: SOC
      due: 24h
      evidence: Source identifies this as a system controlled by the attacker for Certighost exploitation.
    - action: Search AD for machine accounts starting with GHOST
      owner: SOC
      due: 24h
      evidence: Source lists GHOSTAUFTAFGS, GHOSTCZYQVAZS, etc. as telltale signs of CVE-2026-54121 exploitation.
  hunt_leads:
    - lead: Identify scheduled tasks created via PowerShell containing unusual names or paths
      technique_id: T1053.005
      data_needed:
        - Sysmon Event ID 1
        - Security Event ID 4698
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker manually creates scheduled tasks through PowerShell; tasks named sIErKswD, PpMBCCSR.
  mitigation_plan:
    - priority: immediate
      action: Patch AD CS servers for CVE-2026-54121
      owner: IT Operations
      addresses: CVE-2026-54121
      evidence: Source notes exploitation of CVE-2026-54121 for privilege escalation.
---

Citrus Ransomware is a previously undocumented threat actor that utilizes a combination of traditional credential theft and modern automation tools. The group gains initial access through compromised contractor VPN or RDP accounts. Once inside, they use LLM-generated PowerShell scripts to perform internal reconnaissance and system administration. The group actively exploits Active Directory Certificate Services via CVE-2026-54121 (Certighost) to achieve privilege escalation and also targets 1C:Enterprise server configurations.

## Attack Chain
1. Initial Access: Compromised contractor credentials used to access corporate VPNs or RDP.
2. Execution: LLM-generated PowerShell and CMD scripts executed to perform reconnaissance and manage internal tasks.
3. Execution: Usage of Impacket atexec to create scheduled tasks and run commands (e.g., gpupdate).
4. Persistence: Manual creation of scheduled tasks using PowerShell commands.
5. Privilege Escalation: Exploitation of CVE-2026-54121 (Certighost) via Active Directory Certificate Services to request certificates and authenticate as domain controllers.
6. Lateral Movement: Leveraging insecure configurations in 1C:Enterprise servers to move deeper into the environment.

## Impact
Observed impact includes unauthorized access to domain controllers via certificate forgery, execution of arbitrary commands via Impacket, and deployment of Sn00py family ransomware.

## Recommendation
- Patch CVE-2026-54121 on all AD CS servers immediately.
- Audit Active Directory for machine accounts matching the naming convention "GHOST*" followed by random characters.
- Implement strict ingress filtering for RDP and VPN access, specifically auditing contractor account activity.
- Monitor PowerShell activity for scripts containing LLM-style comments.
