---
title: OpenClaw Trusted Retry Endpoint Hostname Bypass
slug: 2026-07-openclaw-hostname-bypass
description: A vulnerability in OpenClaw allows an attacker to bypass trusted retry endpoint validation by crafting a URL with a hostname prefix that resembles a trusted host, which, if the feature is enabled and reachable by lower-trust input, could lead to sensitive authentication material being sent to an unintended external endpoint.
date: "2026-07-03T11:56:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - server-side-request-forgery
  - web-application
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.5.7)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Trusted retry endpoint checks could match hostname prefixes. In affected versions, a retry endpoint URL chosen by lower-trust input could pass validation by using a hostname prefix that resembled a trusted host.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This could send authentication material to an endpoint outside the intended trust target.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-77q5-rr5v-x43q
---

A significant vulnerability has been identified in `OpenClaw`'s trusted retry endpoint checks, published on July 2, 2026. This flaw permits attackers to craft URLs for these endpoints using hostname prefixes that mimic legitimate trusted hosts, thereby bypassing internal validation mechanisms. When `OpenClaw` instances have this feature enabled and are exposed to lower-trust input, they can be coerced into sending sensitive authentication material (such as API keys or tokens) to attacker-controlled infrastructure. This risk highlights the critical importance of secure configuration and timely patching, as the compromise of authentication credentials could lead to unauthorized access, data exfiltration, or further lateral movement within an affected environment. The first stable patched version addressing this issue is `2026.5.7`.

## Attack Chain

1.  Attacker identifies an `OpenClaw` instance where the vulnerable retry endpoint feature is enabled and can process input from lower-trust sources.
2.  Attacker crafts a malicious URL designed to bypass validation, utilizing a hostname prefix that closely resembles a legitimate trusted host (e.g., `trusted.example.com.malicious.net`).
3.  The crafted URL is submitted to the `OpenClaw` instance through an accessible pathway, such as an API endpoint or user-controlled input field.
4.  `OpenClaw`'s vulnerable trusted retry endpoint validation logic incorrectly identifies the attacker's URL prefix as a match for a legitimate trusted host due to the flawed matching algorithm.
5.  `OpenClaw` initiates an outbound network connection to the attacker-controlled domain embedded within the crafted URL.
6.  During the outbound connection, `OpenClaw` inadvertently includes sensitive authentication material (e.g., API keys, session tokens, internal credentials) intended for the genuine trusted host.
7.  The attacker's server receives the incoming connection from the `OpenClaw` instance and captures the exfiltrated authentication material.
8.  The attacker then uses the compromised authentication material to gain unauthorized access to other systems or exfiltrate sensitive data.

## Impact

The primary impact of this vulnerability is the potential exfiltration of sensitive authentication material, such as API keys, session tokens, or other credentials. If exploited, `OpenClaw` instances could unwittingly send these materials to attacker-controlled endpoints, leading to unauthorized access to connected services or systems. The practical consequences for an organization depend heavily on the specific configuration of the `OpenClaw` instance, including whether the affected feature is enabled and reachable by untrusted input, and the criticality of the authentication material being mishandled. This could ultimately result in data breaches, further lateral movement by attackers, or unauthorized control over critical applications.

## Recommendation

*   Upgrade `OpenClaw` to version `2026.5.7` or later immediately to apply the patch addressing the hostname prefix bypass vulnerability, referenced in the affected products `OpenClaw (< 2026.5.7)`.
*   If immediate patching is not possible, implement strict host validation for retry endpoint configurations, ensuring exact trusted origins are specified and not just prefixes, as described by the vulnerability in this brief.
*   Review and disable the affected `OpenClaw` retry endpoint feature if it is not explicitly required in your environment to eliminate the attack surface.
*   Audit `OpenClaw` configurations to ensure that channel and tool allowlists are narrowly defined, preventing lower-trust inputs from reaching sensitive configuration pathways.
