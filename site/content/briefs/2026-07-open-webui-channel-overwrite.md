---
title: Open WebUI Cross-Channel Message Overwrite Vulnerability
slug: 2026-07-open-webui-channel-overwrite
description: An authenticated user can overwrite messages in any channel, including private and DM channels, by exploiting the CVE-2026-59714 authorization bypass vulnerability in Open WebUI's chat completion API, leading to message integrity destruction and impersonation.
date: "2026-07-24T17:05:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web-application
  - api-abuse
  - authorization-bypass
  - ghsa
  - data-manipulation
vendors:
  - Open WebUI
products:
  - Open WebUI (>= 0.9.5, < 0.10.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Any authenticated user can overwrite the content of a message in a channel they do not belong to...
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Bypass User Account Control
    evidence: the `channel:` prefix caused the entire ownership/membership verification block to be skipped, with no channel membership/write check replacing it.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1561
    technique_name: Disk Wipe
    evidence: The overwritten message retains the original author attribution while displaying attacker-chosen content (impersonation).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-x2ff-v5v8-m75m
iocs:
  - type: url
    value: http://target:8080/api/chat/completions
ioc_counts:
  url: 1
---

A high-severity authorization bypass vulnerability, tracked as CVE-2026-59714, has been identified in Open WebUI versions 0.9.5 through 0.9.x, prior to 0.10.0. This flaw allows any authenticated user to overwrite messages in arbitrary channels, including private and direct message channels, even if they are not a member of those channels. The vulnerability resides in the chat completion API, specifically when handling requests with a `channel:`-prefixed `chat_id` and a target `message_id`. This bypasses critical ownership and membership verification steps, leading to unchecked database writes that alter message content while retaining the original author's attribution. This issue results in message integrity destruction and enables impersonation, posing a significant risk to the trustworthiness and privacy of communications within affected Open WebUI instances.

## Attack Chain

1. An authenticated attacker sends a `POST` request to the `/api/chat/completions` API endpoint.
2. The request body includes a `chat_id` parameter prefixed with `channel:`, for example, `channel:any-channel-uuid-here`, and a `message_id` parameter corresponding to a specific message in a target victim channel.
3. When `main.py` processes the request with the `channel:` prefix, it incorrectly bypasses the standard ownership and membership verification checks for the channel.
4. The user-supplied `message_id` from the request body is passed directly to the `_make_channel_emitter` function in `socket/main.py`.
5. The `_make_channel_emitter` function then calls `Messages.update_message_by_id`.
6. `Messages.update_message_by_id` executes a direct primary-key database update using the attacker-provided `message_id` without performing any additional channel ID or user authorization validation.
7. The content of the targeted message in the victim's channel is overwritten with attacker-controlled content.
8. The overwritten message retains the original author's attribution, allowing the attacker to impersonate the legitimate sender.

## Impact

The successful exploitation of CVE-2026-59714 allows any authenticated user to unilaterally overwrite messages in any channel they do not belong to, including private channels and direct messages. This leads to a severe degradation of message integrity and enables sophisticated impersonation attacks, as the altered messages still appear to originate from their original authors. This could be used for spreading misinformation, issuing false instructions, or compromising the privacy and trust within an organization's communication platform. While the advisory does not specify the number of victims or sectors targeted, any organization utilizing vulnerable versions of Open WebUI is at risk of such communication integrity breaches.

## Recommendation

* Patch Open WebUI instances immediately to version `0.10.0` or later to remediate CVE-2026-59714.
* Monitor application logs for `POST` requests to `/api/chat/completions` containing a `chat_id` parameter that starts with `channel:`, especially if the request is not from expected sources or user roles.
* Implement WAF or API gateway rules to inspect the JSON body of `POST /api/chat/completions` requests for the `chat_id` field containing `channel:` and the `message_id` field.
* Review access logs and internal audit trails for any `POST` requests to the `http://target:8080/api/chat/completions` endpoint that occurred on affected versions.
