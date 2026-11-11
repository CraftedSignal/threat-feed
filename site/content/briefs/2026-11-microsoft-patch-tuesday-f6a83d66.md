---
brief_id: brief-2026-11-11-microsoft-patch-tuesday-f6a83d66
event_id: brief-2026-11-11-microsoft-patch-tuesday-f6a83d66
revision: 1
activity_at: "2026-11-11T01:38:42Z"
title: 'Microsoft: November 2026 Patch Tuesday Security Updates'
slug: 2026-11-microsoft-patch-tuesday-f6a83d66
description: Microsoft released 1,252 patches for November 2026, including 68 critical vulnerabilities and one actively exploited zero-day (CVE-2026-124194) involving silent NTLMv2 credential harvesting in Outlook.
date: "2026-11-11T01:38:42Z"
lastmod: "2026-11-11T07:21:24Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-november-2026/
  observed_at: "2026-11-11T07:11:36Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Data points verified against provided CrowdStrike analysis.
cpes:
  - cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:microsoft:office_2021:-:*:*:*:ltsc:-:*:*
  - cpe:2.3:a:microsoft:office_2024:-:*:*:*:ltsc:-:*:*
vendors:
  - Microsoft
products:
  - Windows
  - Outlook
  - Word
  - Active Directory Domain Services
  - Windows Message Queuing
  - Server Message Block
  - Print Spooler
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204.002
    technique_name: Malicious File
    evidence: Exploitation requires the victim to open a malicious file delivered via email or another channel.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557.001
    technique_name: LLMNR/NBT-NS Poisoning and SMB Relay
    evidence: A specially crafted message file can cause Outlook to connect to an attacker-controlled network location without displaying the usual external-content warning, disclosing the victim's NTLMv2 hash.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: CVE-2026-113753, CVE-2026-113856, and CVE-2026-113860 all enable elevation of privilege within the hypervisor boundary.
    confidence_band: high
cves:
  - id: CVE-2026-116928
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-124194
    cvss: 6.5
    kev_status: "false"
  - id: CVE-2026-113753
    kev_status: unknown
  - id: CVE-2026-113856
    kev_status: unknown
  - id: CVE-2026-113860
    kev_status: unknown
  - id: CVE-2026-112967
    kev_status: unknown
references:
  - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-november-2026/
rules:
  - title: Detect Outbound NTLM Authentication from Outlook
    description: Detects unusual network connections originating from Outlook potentially related to credential disclosure attempts
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1557.001
    data_sources:
      - network_connection
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Deploy November 2026 Microsoft security patches across all systems
      owner: IT Operations
      due: 24h
      evidence: Microsoft monthly release addresses 1,252 CVEs including 68 critical vulnerabilities.
  hunt_leads:
    - lead: Identify systems with MSMQ, SMB, or LDAP services exposed to the network
      technique_id: T1190
      data_needed:
        - Network listener logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The unauthenticated network-reachable RCE cluster spans 14 CVEs this month.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for CVE-2026-124194 and related Critical RCEs
      owner: IT Operations
      addresses: CVE-2026-124194, CVE-2026-112967, CVE-2026-116928
      evidence: Confirmed active exploitation for CVE-2026-124194.
updates:
  - at: "2026-11-11T07:21:24Z"
    level: L3
    summary: exploited:true
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-november-2026/
---

The November 2026 security release addresses 1,252 vulnerabilities, with a specific focus on remote code execution (RCE) in identity services (LDAP, AD DS) and preview-pane triggered vulnerabilities in Microsoft Office. A notable zero-day, CVE-2026-124194, is actively exploited in the wild, allowing unprompted NTLMv2 hash disclosure. Critical RCE vulnerabilities (CVE-2026-112967, CVE-2026-116928) present significant risk to Windows network services.

## Impact

Successful exploitation of CVE-2026-124194 allows attackers to capture NTLMv2 hashes for relay or offline cracking. RCE vulnerabilities in LDAP and AD DS provide paths to domain-wide compromise, while privilege escalation flaws in Hyper-V affect both server infrastructure and workstations utilizing Virtualization-Based Security (VBS).

## Recommendation

- Patch all Windows and Office environments immediately, prioritizing systems running AD DS, LDAP, and Hyper-V components.
- Review and implement policies to restrict outbound NTLM traffic at the perimeter to mitigate the impact of hash-leak vulnerabilities.
- Monitor for unexpected network connections initiated by Outlook or office applications to external IP addresses.
