---
brief_id: brief-2026-11-16-sansar-linux-cryptomining
event_id: brief-2026-11-16-sansar-linux-cryptomining
revision: 1
activity_at: "2026-11-16T11:46:16Z"
title: 'REF3364: SANSAR Linux cryptomining malware utilizes rootkit and NVML hooking'
slug: 2026-11-sansar-linux-cryptomining
description: The threat actor REF3364 is leveraging exploited Ray job agents to deploy the SANSAR Linux cryptomining toolkit, which utilizes a kernel rootkit and modified NVIDIA libraries to evade detection and maintain persistence.
date: "2026-11-16T11:46:16Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Content aligned with Elastic Security Labs report cited in the source.
tags:
  - cryptojacking
  - linux
  - malware
  - rootkit
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Initial access is said to have been achieved via an exposed Ray job agent, allowing the threat actor to execute commands.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1014
    technique_name: Rootkit
    evidence: The threat actor also deployed a kernel rootkit to hide selected processes and files.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    evidence: The installation also delivers a modified NVML wrapper that filters process information and changes GPU telemetry to evade detection.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: This backdoor retrieves its C2 address from an Ethereum smart contract before connecting to the server directly.
    confidence_band: high
references:
  - https://thehackernews.com/2026/11/sansar-linux-cryptomining-malware-uses.html
iocs:
  - type: domain
    value: efxisnqldelyr5ra25oqfrsut54b34g26e7zrsiuupsoekjof2gho2id.onion
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Infrastructure Security
  immediate_actions:
    - action: Audit Ray job agents for internet accessibility and restrict access to authorized management networks.
      owner: Infrastructure Security
      due: 24h
      evidence: Initial access is said to have been achieved via an exposed Ray job agent.
    - action: Scan Linux hosts for unusual kernel modules, specifically checking for 'acpi_thermal_mgr.ko'.
      owner: SOC
      due: 24h
      evidence: The 'acpi_thermal_mgr.ko' kernel rootkit uses Function Tracer (ftrace) to conceal cryptomining activity.
  hunt_leads:
    - lead: Hunt for unexpected modifications to the NVIDIA Management Library (NVML) on GPU-enabled servers.
      technique_id: T1562.001
      data_needed:
        - File integrity monitoring logs
        - Binary hash analysis
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Specifically, the altered wrapper hooks NVML calls used by monitoring tools such as nvidia-smi to report GPU utilization as 0%.
    - lead: Investigate Ethereum-related outbound traffic or systemd services identified as 'netns'.
      technique_id: T1071.001
      data_needed:
        - Network traffic logs
        - Systemd unit file analysis
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: netns backdoor is registered as a systemd service. It's used to retrieve a controller IPv4 address by sending requests to an embedded contract.
---

## Overview

The threat actor cluster REF3364 is deploying the SANSAR Linux cryptomining toolkit, a Rust-based orchestrator, to perform illicit GPU and CPU mining. The operation, observed in late October 2026, exploits misconfigured Ray job agents for initial access and employs advanced defense evasion techniques, including kernel-level rootkits and library hooking. The toolkit manages CPU miners (XMRig) and GPU miners (SRBMiner-MULTI) while masking system telemetry.

## Attack Chain

1. Initial access via exploited Ray job agent.
2. Exfiltration of GPU inventory using standard nvidia-smi tools.
3. Execution of a Python-based reverse shell for C2 connectivity.
4. Establishment of persistence via SSH authorized_keys addition.
5. Deployment of the acpi_thermal_mgr.ko kernel rootkit via DKMS.
6. Installation of a modified NVML wrapper to hook monitoring calls and hide GPU load.
7. Activation of the netns backdoor, which retrieves secondary C2 infrastructure from an Ethereum smart contract.

## Impact

Cryptojacking diverts compute resources from legitimate workloads, specifically impacting infrastructure used for AI and LLM processing. The presence of a kernel rootkit and persistent backdoors indicates potential for long-term unauthorized access, credential theft, and lateral movement within the environment.

## Recommendation

Audit all external-facing Ray job agents to ensure restricted access and monitor for unauthorized job submissions. Examine GPU infrastructure for tampered libraries, specifically verifying the integrity of the NVIDIA Management Library (NVML) files. Monitor for suspicious kernel modules loaded via DKMS and inspect initramfs configurations for unauthorized additions.
