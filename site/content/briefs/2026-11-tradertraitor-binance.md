---
brief_id: brief-2026-11-01-tradertraitor-binance
event_id: brief-2026-11-01-tradertraitor-binance
revision: 1
activity_at: "2026-11-01T08:57:56Z"
title: 'TraderTraitor: Large-scale cryptocurrency theft targeting Binance'
slug: 2026-11-tradertraitor-binance
description: The North Korean-aligned actor TraderTraitor (UNC4899) stole $6.43 billion from Binance using recruitment-themed social engineering and trojanized Terraform providers to deploy multi-stage cross-platform malware.
date: "2026-11-01T08:57:56Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - TraderTraitor
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: almost certain
qa_status:
  verdict: pass
tags:
  - cryptocurrency
  - financial-crime
  - nation-state
  - social-engineering
  - supply-chain
vendors:
  - Binance
  - HashiCorp
products:
  - Binance
  - Terraform
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: TraderTraitor's modus operandi employs recruitment-themed lures as a pretext to convince victims to run malicious code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: The poisoned Terraform provider is used to deliver a Bash loader that selects and downloads malware.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1195.002
    technique_name: Compromise Software Supply Chain
    evidence: The activity once again demonstrates how North Korean threat actors continue to abuse trusted developer workflows through trojanized Terraform providers.
    confidence_band: high
references:
  - https://thehackernews.com/2026/11/fbi-links-north-koreas-tradertraitor-to.html
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit environment for the use of non-official or unvetted Terraform providers.
      owner: IT Operations
      due: 48h
      evidence: The poisoned Terraform provider is used to deliver a Bash loader.
  hunt_leads:
    - lead: Hunt for suspicious Bash execution originating from Terraform-related processes or directories.
      technique_id: T1059.004
      data_needed:
        - Process creation logs
        - Command line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The poisoned Terraform provider is used to deliver a Bash loader.
  mitigation_plan:
    - priority: immediate
      action: Implement allow-listing for Terraform providers and disable dynamic loading of providers from untrusted registries.
      owner: IT Operations
      addresses: Terraform supply chain compromise
      evidence: The activity once again demonstrates how North Korean threat actors continue to abuse trusted developer workflows through trojanized Terraform providers.
---

The U.S. Federal Bureau of Investigation (FBI) has attributed a record $6.43 billion cryptocurrency theft from Binance to the North Korea-aligned threat actor TraderTraitor (also known as Jade Sleet, Pressure Chollima, PUKCHONG, Slow Pisces, and UNC4899). The threat actor is known to target individuals in the cybersecurity, AI, and blockchain industries using AI-generated personas and job-themed lures. The group leverages trojanized Terraform providers to deliver a Bash loader, which subsequently installs the FLATROOF cross-platform implant and the ROOFDECK backdoor.

## Attack Chain

1. **Reconnaissance:** The actor identifies targets in the cybersecurity, AI, and blockchain sectors.
2. **Social Engineering:** The actor poses as recruiters using AI-generated personas and industry-specific knowledge to schedule interviews via spoofed front companies.
3. **Delivery:** The target is convinced to download or interact with malicious resources, including trojanized Terraform providers.
4. **Execution:** The Terraform provider executes a Bash loader script.
5. **Staging:** The loader identifies the victim's OS and downloads the appropriate implant (FLATROOF).
6. **Persistence & Control:** The FLATROOF implant exfiltrates data and drops the ROOFDECK backdoor to establish remote command and control.
7. **Exploitation:** The actor utilizes the compromised environment to facilitate the theft and subsequent laundering of virtual assets.

## Impact

- Over $6.43 billion in virtual assets stolen from Binance, the largest cryptocurrency theft in history.
- Approximately $2.85 billion in stolen assets has been frozen on-chain by various entities including Tether, Circle, Ripple, Arbitrum, and Optimism.

## Recommendation

- Implement strict code review processes for any third-party infrastructure-as-code (IaC) modules, specifically Terraform providers.
- Audit outbound network connections from build servers and developer workstations to prevent unexpected downloads of loaders from untrusted external sources.
- Implement endpoint security monitoring to detect the execution of suspicious Bash scripts, Python information stealers, and the specific artifacts associated with FLATROOF and ROOFDECK implants.
- Review recruitment and hiring practices to verify the identity of external recruiters and the legitimacy of job opportunities offered via social media or professional networks.
