---
title: KadNap Botnet Targeting Asus Routers
slug: 2024-01-30-kadnap-botnet
description: The KadNap botnet is delivering malicious payloads targeting Asus routers, indicated by specific SHA256 hashes of MIPS and ARM binaries.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - botnet
  - router
  - kadnap
vendors:
  - Asus
products:
  - Routers
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.circl.lu/doc/misp/feed-osint/2bd1fa00-6450-479c-9387-3a7fcb5e15a9.json
iocs:
  - type: hash_sha256
    value: 0b3dbb951de7a216dd5032d783ba7d0a5ecda2bf872643c3a4ddd1667fb38ffe
  - type: hash_sha256
    value: ebf9de6b67e94b2bd2b0dcda1941e04fef1a1dad830404813e468ab8744b7ed8
ioc_counts:
  hash_sha256: 2
rules:
  - title: Detect KadNap Payload Download via Wget
    description: Detects wget downloading a file from the internet
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - linux
  - title: Detect KadNap Payload File Creation
    description: Detects the creation of KadNap payload files on disk by matching their SHA256 hashes.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The KadNap botnet is actively spreading malware to Asus routers, potentially compromising network security and enabling further malicious activities. Discovered on 2026-03-13, this botnet uses specifically compiled payloads for MIPS and ARM architectures, indicating a focus on embedded devices like routers. The botnet activity can allow attackers to perform a range of actions, including data theft, network exploitation, and use of the compromised devices for distributed denial-of-service (DDoS) attacks. Identifying and blocking these payloads is crucial to prevent further infection and mitigate the impact of the KadNap botnet.

## Attack Chain

1.  The attacker identifies vulnerable Asus routers with default or weak credentials exposed to the internet.
2.  The attacker attempts to brute-force or exploit known vulnerabilities in the router's web interface or other exposed services.
3.  Upon successful authentication or exploitation, the attacker gains remote access to the router's command line interface (CLI).
4.  The attacker downloads the KadNap payload, either the MIPS or ARM variant, depending on the router's architecture, using `wget` or `curl`.
5.  The attacker executes the downloaded payload, granting the KadNap botnet access to the router's resources.
6.  The KadNap payload establishes a connection to a command-and-control (C2) server, receiving instructions and sending back information.
7.  The compromised router is now part of the KadNap botnet, and can be used to launch DDoS attacks, scan for other vulnerable devices, or perform other malicious activities.

## Impact

Successful KadNap infections can lead to significant disruption of network services, data theft, and compromised devices being used as part of a larger botnet for DDoS attacks or other malicious activities. The number of affected devices is currently unknown, but targeting Asus routers indicates a broad potential impact on home and small business networks.

## Recommendation

*   Create file integrity monitoring rules to detect the presence of the KadNap payloads based on their SHA256 hashes: `0b3dbb951de7a216dd5032d783ba7d0a5ecda2bf872643c3a4ddd1667fb38ffe` and `ebf9de6b67e94b2bd2b0dcda1941e04fef1a1dad830404813e468ab8744b7ed8`.
*   Implement the Sigma rule provided below to detect the download of suspicious binaries on network devices.
*   Monitor network traffic for connections originating from Asus routers to unusual or known malicious IP addresses (future enrichment).
