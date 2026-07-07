---
title: Suspicious Process Execution from Linux Shared Memory (/dev/shm)
slug: 2026-07-linux-shm-exec
description: Attackers are abusing the Linux shared memory directory, `/dev/shm`, for fileless malware staging and execution to evade disk-based detection mechanisms, posing a high risk for persistent access and system compromise.
date: "2026-07-03T14:33:33Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Various APTs
  - criminal groups
tags:
  - stealth
  - execution
  - linux
  - memory-abuse
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Detects the execution of a binary from the Linux shared memory directory /dev/shm. This directory is a tmpfs mount backed entirely by RAM and is abused by attackers for fileless malware staging because files written there never touch physical disk and may evade disk-based detection.
    confidence_band: high
references:
  - https://www.sysdig.com/blog/containers-read-only-fileless-malware
  - https://unfinished.bike/fun-with-the-new-bpfdoor-2023
  - https://asiapacificdefencereporter.com/wp-content/uploads/2023/08/Final-CRWD-2023-Threat-Hunting-Report.pdf
  - https://www.crowdstrike.com/en-us/blog/how-to-hunt-for-decisivearchitect-and-justforfun-implant/
  - https://www.linkedin.com/posts/avradeep_malware-apt-infostealer-activity-7373203959697719296-JR-7
  - https://www.stormshield.com/news/orbit-analysis-of-a-linux-dedicated-malware/
rules:
  - title: Process Execution From Shared Memory Directory
    description: Detects the execution of a binary from the Linux shared memory directory /dev/shm, a known technique for fileless malware staging.
    platform: sigma
    severity: high
    tactics:
      - execution
      - stealth
    techniques:
      - T1027.011
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Attackers are increasingly leveraging the Linux shared memory directory, `/dev/shm`, as a stealthy staging ground for malicious executables. This directory functions as a `tmpfs` mount, meaning it resides entirely in RAM, preventing files written within it from ever touching physical disk. This characteristic makes it an attractive location for fileless malware, as it can bypass traditional disk-based forensic tools and detection mechanisms. The technique has been observed in campaigns by various advanced persistent threat (APT) groups and criminal organizations, notably linked to implants like BPFDoor, DecisiveArchitect, JustForFun, and Orbit malware, indicating its widespread adoption in Linux-focused attacks. The abuse of `/dev/shm` primarily aims at achieving execution while maintaining a low footprint, making detection challenging for defenders who are not actively monitoring process creation from this specific, often overlooked, directory.

## Attack Chain

1.  **Initial Access:** Attackers gain initial access to a Linux system, often via exploiting vulnerable internet-facing services (e.g., SSH, web applications), weak credentials, or phishing.
2.  **Foothold & Staging:** Once a foothold is established, the adversary typically downloads or stages malicious payloads, scripts, or binaries onto the compromised system.
3.  **Fileless Staging in /dev/shm:** To evade disk-based detection, the malicious executable is written directly into the `/dev/shm` directory, ensuring it resides only in memory.
4.  **Execution from Shared Memory:** The attacker then initiates the execution of the payload from `/dev/shm/`, masquerading it as a legitimate process or leveraging common execution methods.
5.  **Implant Deployment/Execution:** The executed binary establishes persistence, deploys additional implants, or performs initial reconnaissance on the compromised system.
6.  **Command and Control (C2):** A C2 channel is established for remote management, data exfiltration, or further instruction delivery.
7.  **Impact:** Depending on the attacker's objective, this may lead to data theft, cryptomining, resource hijacking, or the establishment of a long-term presence for future operations.

## Impact

The successful exploitation of this technique can lead to significant compromise of Linux systems, ranging from data exfiltration and intellectual property theft to resource hijacking for cryptomining, and the establishment of persistent backdoors. Because malware executed from `/dev/shm` leaves minimal forensic artifacts on disk, incident response and forensic analysis become significantly more challenging, increasing the dwell time of attackers. While no specific victim counts are tied to this generalized technique in the source material, its use by sophisticated APT groups implies targeting of high-value organizations across various sectors, including government, technology, and critical infrastructure. The primary impact is reduced visibility and increased stealth for adversaries.

## Recommendation

*   Deploy the provided Sigma rule "Process Execution From Shared Memory Directory" to your SIEM.
*   Ensure `process_creation` logging is enabled for all Linux endpoints to capture `Image` paths required by the rule.
*   Review any legitimate applications or container runtimes that might legitimately execute processes from `/dev/shm` to tune false positives for the "Process Execution From Shared Memory Directory" rule.
