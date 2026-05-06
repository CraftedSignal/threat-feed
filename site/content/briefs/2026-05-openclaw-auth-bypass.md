---
title: OpenClaw Authorization Bypass Vulnerability (CVE-2026-44110)
slug: 2026-05-openclaw-auth-bypass
description: OpenClaw before 2026.4.15 contains an authorization bypass vulnerability that allows attackers with DM-paired sender IDs to execute room control commands without being in configured allowlists, potentially enabling privileged OpenClaw behavior by posting in bot rooms.
date: "2026-05-06T20:16:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization bypass
  - matrix
  - bot
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-44110
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44110
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-2gvc-4f3c-2855
  - https://www.vulncheck.com/advisories/openclaw-authorization-bypass-in-matrix-room-control-commands-via-dm-pairing-store
rules:
  - title: Detect OpenClaw Room Control Command Abuse
    description: Detects suspicious Matrix messages indicative of OpenClaw room control command abuse
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw DM Pairing Activity
    description: Detects direct messages to the OpenClaw bot that might indicate pairing activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a Matrix bot, is vulnerable to an authorization bypass (CVE-2026-44110) affecting versions prior to 2026.4.15. This vulnerability stems from the Matrix room control-command authorization logic trusting DM pairing-store entries without proper validation against configured allowlists. An attacker who has established a DM pairing with the bot can exploit this flaw to execute room control commands by posting in bot rooms, even if they are not explicitly authorized. This can lead to unauthorized modification of room settings or execution of other privileged bot functionalities. The vulnerability was reported by VulnCheck and patched in version 2026.4.15. Defenders should upgrade to the latest version of OpenClaw to mitigate this risk.

## Attack Chain

1.  Attacker establishes a direct message (DM) pairing with the OpenClaw bot.
2.  The bot stores the DM pairing information.
3.  Attacker identifies a bot room where OpenClaw is active.
4.  Attacker crafts a room control command, such as a command to change room settings.
5.  Attacker posts the malicious command within the bot room.
6.  OpenClaw receives the command and incorrectly trusts the DM pairing-store entry for authorization.
7.  OpenClaw executes the room control command with elevated privileges, bypassing configured allowlists.
8.  The attacker successfully modifies the room settings or triggers other privileged behavior.

## Impact

Successful exploitation of CVE-2026-44110 allows unauthorized users to execute privileged commands within Matrix rooms controlled by OpenClaw. This could result in significant disruption, including unauthorized modification of room settings, disclosure of sensitive information, or other malicious activities enabled by OpenClaw's functionality. The severity is compounded by the ease of exploitation, requiring only a pre-existing DM pairing with the bot. The impact depends on the specific functionalities and permissions granted to the OpenClaw bot within the affected Matrix environment.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.15 or later to patch CVE-2026-44110 (see References).
*   Review and restrict the permissions granted to the OpenClaw bot within Matrix rooms to minimize potential impact from unauthorized command execution.
*   Implement the Sigma rule "Detect OpenClaw Room Control Command Abuse" to identify suspicious command activity within bot rooms.
*   Monitor Matrix room activity logs for unauthorized modifications or actions performed by the OpenClaw bot.
*   Enable logging of Matrix bot commands to aid in investigation and auditing of potential authorization bypass attempts.
