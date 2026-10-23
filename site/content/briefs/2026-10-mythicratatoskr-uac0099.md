---
brief_id: brief-2026-10-23-mythicratatoskr-uac0099
event_id: brief-2026-10-23-mythicratatoskr-uac0099
revision: 1
activity_at: "2026-10-23T08:57:26Z"
title: 'UAC-0099 and Sandworm collaboration: MythicRatatoskr backdoor and destructive wiping'
slug: 2026-10-mythicratatoskr-uac0099
description: UAC-0099 gained initial access to a Ukrainian organization via spearphishing to deploy the MythicRatatoskr backdoor, which uses the Yggdrasil mesh network for C2, before handing off access to Sandworm for destructive data-wiping.
date: "2026-10-23T08:57:26Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - Sandworm
  - BlackEnergy
  - Voodoo Bear
  - Seashell Blizzard
  - IRIDIUM
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
  - backdoor
  - wiper
  - uac-0099
  - sandworm
  - yggdrasil
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    subtechnique_id: T1566.001
    subtechnique_name: Spearphishing Attachment
    evidence: UAC-0099 gained initial access by sending spearphishing emails containing a malicious attachment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: MythicRatatoskr can execute shell commands using cmd.exe.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543.003
    technique_name: Windows Service
    subtechnique_id: T1543.003
    subtechnique_name: Windows Service
    evidence: MythicRatatoskr persists as a Windows service.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090.003
    technique_name: Multi-hop Proxy
    subtechnique_id: T1090.003
    subtechnique_name: Multi-hop Proxy
    evidence: MythicRatatoskr connects to the C&C server within the Yggdrasil mesh network.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The data-wiping attack was executed by deploying the SDelete utility via Active Directory Group Policy
    confidence_band: high
references:
  - https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration/
iocs:
  - type: url
    value: https://uztickets.com
  - type: url
    value: https://egyptanimals.com/animals/photoalbum
ioc_counts:
  url: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block the identified MATCHWOK C2 and staging URLs in the perimeter firewall/proxy.
      owner: SOC
      due: 2h
      evidence: Observed C2 and delivery URLs in source.
  hunt_leads:
    - lead: Identify scheduled tasks named pdfopentask and trace the parent process (likely PowerShell).
      technique_id: T1053.005
      data_needed:
        - Windows Event ID 4698
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: at 06:59 on July 16th, 2025, a scheduled task named pdfopentask was executed
    - lead: Search for Yggdrasil-related IPv6 traffic or unexpected mesh networking binaries.
      technique_id: T1071.001
      data_needed:
        - Netflow
        - Host network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: MythicRatatoskr ... hiding its C&C server inside the Yggdrasil mesh network
  mitigation_plan:
    - priority: immediate
      action: Restrict execution of SDelete and similar administrative tools to authorized security/IT accounts only.
      owner: IT Operations
      addresses: Sandworm destructive tactics
      evidence: data-wiping attack was executed by deploying the SDelete utility via Active Directory Group Policy
---

ESET research identified a collaboration between UAC-0099 and Sandworm targeting a Ukrainian grain logistics firm. UAC-0099 provided initial access via spearphishing and the MATCHWOK backdoor, subsequently deploying the novel Go-based 'MythicRatatoskr' backdoor. This backdoor leverages the Yggdrasil decentralized mesh network for C2 communications, providing robust, non-centralized connectivity. After lateral movement and the deployment of proxy tools, Sandworm executed a destructive data-wiping attack using SDelete via Active Directory Group Policy.

## Attack Chain
1. Initial Access: UAC-0099 delivered a malicious attachment via spearphishing email (July 16, 2025).
2. Execution: A scheduled task 'pdfopentask' executed a PowerShell payload from %temp%.
3. Downloader: Deployment of the MATCHBOIL downloader to fetch and execute the MATCHWOK backdoor.
4. Backdoor Deployment: Delivery of the MythicRatatoskr backdoor, which persists as a Windows service.
5. Lateral Movement: Additional MythicRatatoskr samples deployed to other hosts via OpenSSH SFTP.
6. Proxy Deployment: Deployment of a SOCKS5 server via MythicRatatoskr to facilitate internal pivoting.
7. Impact: Sandworm deployed SDelete via Active Directory Group Policy to perform data wiping (September 17, 2025).

## Impact
The campaign resulted in the compromise of multiple internal systems and culminated in destructive data-wiping operations against the target organization, leading to significant operational disruption.

## Recommendation
- Deploy detection for atypical Windows services, particularly those running Go-compiled binaries that exhibit Yggdrasil mesh networking characteristics.
- Monitor for the creation of scheduled tasks named 'pdfopentask' and unauthorized PowerShell execution from temporary directories.
- Audit Active Directory Group Policy objects for the unauthorized distribution of utility tools such as SDelete.
- Hunt for outbound traffic over non-standard ports or encrypted overlay networks (specifically Yggdrasil-related IPv6 traffic) originating from internal assets.
