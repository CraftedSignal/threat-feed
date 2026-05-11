---
title: Open WebUI Insecure Direct Object Reference in Channel Messages
slug: 2026-05-open-webui-idor
description: Open WebUI versions 0.6.18 and earlier are vulnerable to an insecure direct object reference (IDOR) in the channels message management system; authenticated users with read access to a channel can modify or delete any message within that channel due to missing message ownership validation in the message update and delete endpoints.
date: "2026-05-11T14:08:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - privilege-escalation
  - defense-evasion
  - cloud
vendors:
  - Open WebUI
products:
  - open-webui (<= 0.6.18)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1213
    technique_name: Insecure File or Resource Permissions
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-jxwr-g6r6-j3fx
rules:
  - title: Detect Open WebUI Message Modification via IDOR
    description: Detects CVE-2026-44569 exploitation -- unauthorized message modification in Open WebUI due to missing ownership validation, identified by POST requests to the message update endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
  - title: Detect Open WebUI Message Deletion via IDOR
    description: Detects CVE-2026-44569 exploitation -- unauthorized message deletion in Open WebUI due to missing ownership validation, identified by DELETE requests to the message delete endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions 0.6.18 and earlier contain an Insecure Direct Object Reference (IDOR) vulnerability within the channel message management system. This flaw allows authenticated users with read access to a channel to modify or delete messages created by other users within the same channel. The vulnerability stems from the absence of message ownership validation in the backend API endpoints responsible for updating and deleting messages. While the frontend implements client-side checks to restrict message editing and deletion to owners or administrators, these controls can be bypassed by directly interacting with the backend APIs, allowing unauthorized message tampering and deletion. This poses a risk to message integrity and auditability within collaborative channel environments. The issue was reported on May 11, 2026.

## Attack Chain

1. Attacker authenticates to the Open WebUI application.
2. Attacker gains read access to a channel.
3. Victim creates a message within the channel.
4. Attacker observes the `message_id` of the victim's message, either through the frontend or by intercepting API requests.
5. Attacker crafts a malicious API request to either update the message content or delete the message, using the victim's `message_id` and the channel's ID.
6. Attacker sends the crafted API request to the `/api/v1/channels/{channel_id}/messages/{victim_message_id}/update` or `/api/v1/channels/{channel_id}/messages/{victim_message_id}/delete` endpoint, bypassing frontend controls.
7. The backend API validates the attacker's channel access (read permission) but fails to verify message ownership.
8. The victim's message is modified or deleted, leading to data manipulation or denial of service.

## Impact

Successful exploitation of this IDOR vulnerability enables unauthorized modification and deletion of messages within Open WebUI channels. Users with only read access can gain write/delete capabilities over other users' content, potentially leading to the alteration of critical information, disruption of communication, and undermining the integrity of audit trails. This vulnerability affects Open WebUI instances with channels enabled, potentially impacting any collaborative environments relying on message integrity.

## Recommendation

*   Deploy the Sigma rule "Detect Open WebUI Message Modification via IDOR" to identify potential exploitation attempts by monitoring POST requests to the message update endpoint (`/api/v1/channels/{channel_id}/messages/{victim_message_id}/update`) and DELETE requests to the message delete endpoint (`/api/v1/channels/{channel_id}/messages/{victim_message_id}/delete`) in the `webserver` logs.
*   Apply the remediation steps recommended by the vendor, which includes implementing proper message ownership validation in the update and delete endpoints to prevent unauthorized message modification and deletion.
*   Upgrade Open WebUI to a version later than 0.6.18 to patch CVE-2026-44569.
