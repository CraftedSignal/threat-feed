---
title: Kaspersky Anti-Virus Reverse Engineering for Document Detection
slug: 2024-01-kaspersky-av-signature-analysis
description: A blog post details the reverse engineering of the Kaspersky anti-virus engine on macOS to demonstrate the potential for crafting signatures capable of detecting and flagging classified documents, leveraging the product's scanning capabilities and dynamic signature updates, without implying any malicious activity by Kaspersky.
date: "2024-01-26T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - anti-virus
  - reverse-engineering
  - signature-analysis
  - macos
vendors:
  - Kaspersky
products:
  - Kaspersky Internet Security
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://objective-see.org/blog/blog_0x22.html
rules:
  - title: Detect Access to Kaspersky Signature Directories
    description: Detects processes attempting to access or modify files within the Kaspersky signature database directory, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - macos
  - title: Detect Suspicious Process accessing Kaspersky Signature Cache
    description: Detects processes attempting to read the Kaspersky signature cache file, which could indicate an attempt to reverse engineer or tamper with the anti-virus engine.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - macos
rules_count: 2
---

The blog post examines the inner workings of Kaspersky Internet Security for macOS, specifically focusing on its signature update mechanism and the architecture of its scanning engine. It highlights how anti-virus products, due to their inherent need to scan all files, including documents, for malicious patterns, could theoretically be repurposed to identify and flag documents containing specific classification markers. The author reverses the Kaspersky product to understand how to craft a signature that could detect classified documents. The analysis focuses on the `kav` daemon, responsible for the core anti-virus scanning and detection logic. The blog post emphasizes that the analysis is purely for research purposes and does not suggest any actual subversion or misuse by Kaspersky. The target version was the latest version of Kaspersky Internet Security for macOS at the time of the blog post (January 1, 2018).

## Attack Chain

1.  Attacker downloads and installs Kaspersky Internet Security for macOS.
2.  Attacker identifies the `kav` daemon as the core component for scanning and detection logic.
3.  Attacker reverse engineers the `kav` daemon to understand its signature format and scanning logic.
4.  Attacker observes the signature update process where encrypted signatures are downloaded from Kaspersky's update servers (e.g., dnl-03.geo.kaspersky.com) and stored temporarily in `/private/tmp/temporaryFolder/updates/kdb/i386/`.
5.  Attacker discovers that signature updates are installed to `/Library/Application Support/Kaspersky Lab/KAV/Bases/KLAVA/`.
6.  Attacker notes the signatures are stored in a cache file `kavbase_00000000` which is exclusively opened by the `kav` daemon.
7.  Attacker bypasses the need to decrypt the signature database by interacting with signatures in memory.
8.  Attacker crafts a custom signature designed to detect specific classification markers within documents, demonstrating the potential for exfiltration of sensitive information.

## Impact

Successful crafting and deployment of a malicious signature within a subverted anti-virus product could enable the unauthorized detection and exfiltration of documents containing specific classification markers. While the blog post does not detail a real-world attack or any victims, it highlights a potential vulnerability in anti-virus architectures that could be exploited by malicious actors. If successful, sensitive or classified documents could be identified, copied, and sent to attacker-controlled systems without the user's knowledge or consent.

## Recommendation

*   Monitor for suspicious network connections originating from anti-virus processes to unusual or external domains, based on the `network_connection` category and `product: windows` log source.
*   Implement a detection rule (like the example Sigma rule provided) to alert on unauthorized file access or modification attempts to anti-virus signature directories such as `/Library/Application Support/Kaspersky Lab/KAV/Bases/KLAVA/`, as identified in the attack chain.
*   Monitor for processes interacting with Kaspersky's signature cache file (`/Library/Application Support/Kaspersky Lab//KAV/Bases/Cache/kavbase_00000000`), using a `file_event` category log source and a process monitoring tool like Sysmon or auditd.
