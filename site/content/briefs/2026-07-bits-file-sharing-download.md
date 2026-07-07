---
title: BITS Transfer Job Downloads from File Sharing Domains
slug: 2026-07-bits-file-sharing-download
description: Adversaries leverage the Windows Background Intelligent Transfer Service (BITS) to download malicious payloads from legitimate file-sharing and cloud storage domains, enabling stealthy ingress of tools and malware onto compromised systems, a technique observed in campaigns by ransomware groups and nation-state actors.
date: "2026-07-03T15:03:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - execution
  - defense-evasion
  - ingress-tool-transfer
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1197
    technique_name: BITS Jobs
    evidence: Detects BITS transfer job downloading files from a file sharing domain, a technique used by adversaries to blend in with legitimate network traffic.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: BITS transfer job downloading files from a file sharing domain, used to bring additional tools or payloads into an environment.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: ""
    evidence: BITS jobs often leverage standard HTTP/HTTPS protocols for downloads from file-sharing domains, which aligns with common web protocols for C2 or payload retrieval.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md
  - https://twitter.com/malmoeb/status/1535142803075960832
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
  - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
rules:
  - title: BITS Transfer Job Download From File Sharing Domains
    description: Detects BITS transfer job downloading files from legitimate file-sharing or cloud storage domains, a common technique for stealthy ingress of malicious payloads.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
      - stealth
    techniques:
      - T1071.001
      - T1105
      - T1197
    data_sources:
      - file_event
      - windows
      - bits-client
rules_count: 1
---

The Windows Background Intelligent Transfer Service (BITS) is a legitimate component of the operating system designed for asynchronous, prioritized, and throttled transfer of files between machines. Threat actors frequently abuse BITS to download additional malicious tools, payloads, or command and control (C2) configurations onto compromised systems. This technique allows them to blend in with legitimate network traffic, as BITS often utilizes standard HTTP/HTTPS protocols and can bypass some traditional network defenses. The observed activity involves BITS transfer jobs specifically downloading files from popular, legitimate file-sharing or cloud storage domains, such as `githubusercontent.com`, `cdn.discordapp.com`, `mega.nz`, and `storage.googleapis.com`. This approach provides attackers with a relatively trusted channel to stage and retrieve their malicious assets, making detection more challenging. The technique has been observed in campaigns by ransomware groups like Hive, Conti, and AvosLocker, as well as nation-state actors like Mint Sandstorm targeting high-profile individuals.

## Attack Chain

1. An adversary gains initial execution on a target system through various means (e.g., exploiting a vulnerability, phishing).
2. To avoid detection and ensure reliable payload delivery, the attacker decides to use a trusted Windows service for ingress.
3. The attacker programmatically (e.g., via PowerShell or a custom tool) or through `bitsadmin.exe` creates a new BITS transfer job.
4. The BITS job is configured to download a malicious executable or script from a URL hosted on a legitimate, but abused, file-sharing or cloud storage service (e.g., `anonfiles.com`, `mega.nz`).
5. The attacker initiates or schedules the BITS job, allowing the download to proceed in the background, resilient to network interruptions.
6. The BITS client successfully transfers the malicious file to a local staging directory on the compromised host. This activity generates a BITS Client Event ID 16403.
7. The attacker then executes the newly downloaded payload, which could be anything from a backdoor, ransomware, or additional reconnaissance tools.
8. This leads to further compromise, such as data exfiltration, lateral movement, or the deployment of ransomware, achieving the attacker's final objective.

## Impact

Successful exploitation using BITS for ingress typically results in the stealthy delivery and execution of secondary payloads. This can range from installing persistent backdoors for long-term access, deploying ransomware to encrypt critical data and extort payment, to exfiltrating sensitive information. The use of legitimate file-sharing services and BITS makes it harder for security teams to differentiate malicious activity from benign operations, leading to delayed detection and containment. Campaigns leveraging this technique have impacted various sectors, including universities and research organizations, indicating a broad targeting scope. The ultimate damage depends on the nature of the delivered payload, but it often includes financial loss, reputational damage, and operational disruption.

## Recommendation

*   Deploy the provided Sigma rule "BITS Transfer Job Download From File Sharing Domains" to detect suspicious BITS activity targeting common file-sharing domains.
*   Ensure BITS client operational logs (Event ID 16403) are enabled and collected in your SIEM for comprehensive monitoring of file transfers.
*   Review network egress policies to restrict direct access to known file-sharing and cloud storage services from non-essential endpoints, where feasible, to mitigate the risk of BITS abuse.
*   Implement application whitelisting to prevent the execution of unauthorized payloads downloaded via BITS or any other method, thereby limiting the impact of successful ingress.
