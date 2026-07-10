---
title: Freeciv21 Stack Overflow Vulnerability (CVE-2026-33250)
slug: 2024-01-30-freeciv21-stack-overflow
description: Freeciv21 versions prior to 3.1.1 are vulnerable to a stack overflow when processing specially-crafted packets, allowing a remote attacker to crash public servers or a malicious server to crash a player's game.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - freeciv21
  - stack-overflow
  - denial-of-service
  - cve-2026-33250
  - linux
vendors:
  - Freeciv21
products:
  - Freeciv21
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33250
rules:
  - title: Detect Suspicious Network Traffic to Freeciv21 Server
    description: Detects network connections with high data transfer to the Freeciv21 server port, which might indicate a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
  - title: Detect Freeciv21 Server Crash
    description: Detects Freeciv21 server process termination that may indicate a crash due to CVE-2026-33250.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Freeciv21, a free and open-source turn-based strategy game, is susceptible to a critical stack overflow vulnerability (CVE-2026-33250) in versions prior to 3.1.1. This flaw arises from the improper handling of specially-crafted network packets. An unauthenticated remote attacker can leverage this vulnerability to trigger a denial-of-service (DoS) condition by crashing public Freeciv21 servers. Alternatively, a malicious Freeciv21 server can exploit this vulnerability to crash the game client running on a player's machine. The default logging configuration does not provide sufficient information to effectively diagnose or investigate exploitation attempts. Users are advised to upgrade to Freeciv21 version 3.1.1 to remediate this vulnerability. Implementing a firewall to protect non-public servers is also recommended as a mitigation strategy. Local games, which restrict connections to the current user, are not affected by this vulnerability.

## Attack Chain

1.  Attacker identifies a vulnerable Freeciv21 server running a version prior to 3.1.1.
2.  Attacker crafts a malicious network packet designed to trigger a stack overflow.
3.  Attacker sends the specially-crafted packet to the vulnerable Freeciv21 server.
4.  The Freeciv21 server processes the malicious packet, leading to a stack overflow.
5.  The stack overflow corrupts the server's memory, causing the server application to crash.
6.  (Alternative) A player connects to a malicious Freeciv21 server.
7.  The malicious server sends a specially-crafted packet to the player's Freeciv21 client.
8.  The client processes the packet, causing a stack overflow and crashing the game on the player's machine, resulting in a denial-of-service condition for the player.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition. For public Freeciv21 servers, this means the server becomes unavailable to legitimate players, disrupting gameplay and potentially impacting the server's reputation. If exploited against a player's client, it crashes the game, causing frustration and loss of progress. The number of affected servers and players depends on the adoption rate of the vulnerable Freeciv21 versions.

## Recommendation

*   Upgrade all Freeciv21 server and client installations to version 3.1.1 to patch CVE-2026-33250.
*   Deploy the Sigma rule `Detect Suspicious Network Traffic to Freeciv21 Server` to identify potentially malicious packets sent to Freeciv21 servers.
*   Implement a firewall in front of Freeciv21 servers to restrict access and potentially mitigate the impact of malicious packets as mentioned in the overview.
