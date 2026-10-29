---
brief_id: brief-2026-10-29-aur0ra-ransomware-ai
event_id: brief-2026-10-29-aur0ra-ransomware-ai
revision: 1
activity_at: "2026-10-29T15:28:54Z"
title: 'GOLD OGRE: AI-Assisted Intrusion and Aur0ra Ransomware Operations'
slug: 2026-10-aur0ra-ransomware-ai
description: The GOLD OGRE threat group leverages agentic AI frameworks, including Cursor AI and LLMs, to automate post-exploitation tasks, evade EDR, and conduct Aur0ra ransomware attacks.
date: "2026-10-29T15:28:54Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - GOLD OGRE
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - ransomware
  - ai-assisted
  - gold-ogre
  - aur0ra
  - cobalt-strike
  - exfiltration
vendors:
  - Microsoft
  - Veeam
products:
  - Active Directory
  - Windows Server
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087.002
    technique_name: Domain Account
    evidence: The agents then performed network and AD discovery tasks, analyzed credential-based attack paths
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: agents searched network shares, user documents, backup repositories... while conducting password spraying, Kerberoasting, NTLM coercion and relay, and credential extraction
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: AI guardrails were bypassed by framing the intrusions as authorized red team activity or "diagnostics testing".
    confidence_band: high
references:
  - https://www.sophos.com/en-us/blog/ai-used-in-aur0ra-ransomware-testing-and-execution
iocs:
  - type: ip
    value: 152.236.4.14
  - type: ip
    value: 172.86.113.245
  - type: ip
    value: 45.59.113.63
ioc_counts:
  ip: 3
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block C2 and Proxy IPs provided in the IOC table
      owner: SOC
      due: 4h
      evidence: Observed C2 and SOCKS proxy infrastructure associated with Aur0ra ransomware
  hunt_leads:
    - lead: Identify unauthorized use of AI/IDE tools like Cursor in the production environment
      technique_id: T1059
      data_needed:
        - Process creation logs
        - Software inventory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sophos analysts recovered Cursor artifacts associated with Aur0ra ransomware operations and EDR evasion testing.
  mitigation_plan:
    - priority: immediate
      action: Implement SMB signing and disable NTLM relay where possible
      owner: IT Operations
      addresses: NTLM coercion and relay techniques
      evidence: agents searched network shares... while conducting... NTLM coercion and relay
---

Sophos analysts identified the GOLD OGRE threat group using AI-assisted frameworks to orchestrate ransomware operations. The actors utilize Cursor AI, alongside Anthropic, xAI, and Moonshot models, to bypass security controls and automate post-exploitation activities. By framing malicious tasks as authorized "red team activity" or "diagnostics," actors use agentic AI to escalate privileges, enumerate Active Directory, and perform lateral movement before deploying Aur0ra ransomware.

## Attack Chain

1. Initial Access: Operators provide VPN credentials and SOCKS access to AI agents.
2. EDR Evasion Testing: Actors use Cursor AI-assisted frameworks to test detection capabilities against security agents.
3. Internal Discovery: Agents execute Nmap and NetExec to scan subnets and BloodHound to map Active Directory.
4. Privilege Escalation: Agents conduct Kerberoasting, NTLM relay attacks (e.g., PetitPotam, Coerce Plus), and credential extraction.
5. Lateral Movement: Agents enumerate network shares, backup repositories, and virtualization endpoints.
6. Data Collection: Tools like SharpShares are used to stage data from shares and documents.
7. Exfiltration: Staged data is exfiltrated to S3-compatible storage buckets via command-line tools.
8. Impact: Deployment of Aur0ra ransomware and subsequent data leakage on extortion sites.

## Recommendation

- Monitor for anomalous use of AI/IDE tools like Cursor in enterprise environments, especially if used to execute network commands or enumeration tools.
- Audit and restrict NTLM authentication pathways and enforce SMB signing to mitigate relay attacks (e.g., PetitPotam).
- Implement stringent egress filtering to prevent unauthorized data exfiltration to non-approved S3-compatible storage endpoints.
- Review and tighten access to backup repositories and virtualized infrastructure to prevent bulk data staging.
