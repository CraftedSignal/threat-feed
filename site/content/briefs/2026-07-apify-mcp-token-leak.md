---
title: 'Apify Model Context Protocol (MCP) server: Actor MCP path authority injection leaks Apify token'
slug: 2026-07-apify-mcp-token-leak
description: An attacker can exploit a Server-Side Request Forgery (SSRF) vulnerability in `@apify/actors-mcp-server` version `0.10.7` by crafting a malicious Actor definition to inject an arbitrary authority into a URL, causing the MCP client to exfiltrate the victim's Apify API token to the attacker's server, granting full access to their Apify account.
date: "2026-07-03T12:22:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssp-injection
  - ssrf
  - token-exfiltration
  - npm-package
  - cloud
  - saas
vendors:
  - Apify
products:
  - '@apify/actors-mcp-server (0.10.7)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who publishes a malicious Actor with a crafted `webServerMcpPath` (...) can cause the MCP client to resolve the final URL to an entirely different host.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'Because the MCP client unconditionally attaches the victim''s `Authorization: Bearer <APIFY_TOKEN>` header to every outbound connection, the victim''s Apify API token is exfiltrated to the attacker''s server.'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: 'the victim''s Apify API token is exfiltrated to the attacker''s server. (...) `Authorization: Bearer <APIFY_TOKEN>` is sent to the attacker''s host.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6gr2-qh89-hxwm
iocs:
  - type: domain
    value: attacker.example
  - type: url
    value: https://real-actor-id.apify.actor@attacker.example/mcp
ioc_counts:
  domain: 1
  url: 1
---

A critical Server-Side Request Forgery (SSRF) vulnerability, tracked as GHSA-6gr2-qh89-hxwm, exists in `@apify/actors-mcp-server` version `0.10.7` and earlier. This flaw allows an attacker to exfiltrate Apify API tokens from users who interact with a specially crafted malicious Actor. The vulnerability stems from improper validation of the `webServerMcpPath` value, which is sourced from an attacker-controlled Actor definition. By injecting an authority (e.g., `@attacker.example/mcp`) into this path, an attacker can redirect the MCP client's outbound connection to an arbitrary host. Crucially, the MCP client unconditionally attaches the victim's `Authorization: Bearer <APIFY_TOKEN>` header to these outbound connections, leading to the silent exfiltration of the API token. This grants the attacker full access to the victim's Apify account, enabling actions such as running and managing Actors, accessing stored data, and incurring compute charges, without requiring special privileges or code execution on the victim's machine.

## Attack Chain

1.  An attacker publishes a malicious Actor on the Apify platform, crafting its definition to include a `webServerMcpPath` value designed for URL authority injection (e.g., `@attacker.example/mcp`).
2.  A victim, running `@apify/actors-mcp-server` (version `0.10.7` or earlier) and configured with an Apify API token, initiates an MCP tool call (e.g., `call-actor` or `fetch-actor-details`) targeting the attacker-controlled Actor.
3.  The `apifyToken` is resolved from environment variables, server options, or the MCP request's `_meta.apifyToken`.
4.  The application fetches the attacker's Actor definition from the Apify API, retrieving the malicious `webServerMcpPath`.
5.  The `getActorMCPServerURL()` function receives the `webServerMcpPath`, trims and splits it, but crucially performs no validation against authority injection.
6.  The function then concatenates a trusted `standbyUrl` with the malicious `mcpServerPath`, creating an authority-injected URL (e.g., `https://real-actor-id.apify.actor@attacker.example/mcp`).
7.  The `connectMCPClient()` function is invoked with this crafted URL and the victim's Apify API token.
8.  The `connectMCPClient()` then establishes an outbound HTTP connection to the attacker's server (`attacker.example`), sending the victim's `Authorization: Bearer <APIFY_TOKEN>` header, thereby exfiltrating the token.

## Impact

Any user of `@apify/actors-mcp-server` versions prior to `0.10.8` who has an Apify API token configured and is induced to invoke an MCP tool against an attacker-controlled Actor will have their Apify API token silently exfiltrated. The exfiltrated token grants the attacker full administrative access to the victim's Apify account, allowing them to run, manage, and modify Actors, access sensitive data stored within the account, and potentially incur significant compute charges. The attack requires no special privileges on the victim's side and no code execution on their machine, only the interaction with a malicious Actor on the Apify platform, posing a significant risk to the integrity and confidentiality of user accounts.

## Recommendation

*   Immediately update `@apify/actors-mcp-server` to version `0.10.8` or newer to remediate the URL authority injection vulnerability (GHSA-6gr2-qh89-hxwm).
*   Implement strict outbound network egress filtering to prevent unauthorized connections to unknown or untrusted domains, specifically monitoring for connections from `@apify/actors-mcp-server` processes that contain `Authorization: Bearer` headers directed to domains other than `*.apify.com` or other explicitly allowed Apify infrastructure.
*   Consider using dedicated network monitoring tools to detect connections to suspicious IP addresses or domains (e.g., `attacker.example` or `127.0.0.1` as seen in PoC) from your Apify infrastructure.
