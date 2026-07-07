---
title: Rancher Fleet Unauthenticated Webhook Regex Injection (CVE-2026-44937)
slug: 2026-07-rancher-fleet-regex-injection
description: An unauthenticated regex injection vulnerability exists in Rancher Fleet's webhook endpoint when it's configured without a secret, allowing attackers to forge webhook requests using unsanitized repository URL components, which leads to continuous repository re-cloning, causing network and resource exhaustion (Denial of Service) on the management cluster, and potentially service downgrades if the attacker has read access to the target Git repository.
date: "2026-07-03T12:26:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rancher
  - fleet
  - vulnerability
  - webhook
  - regex-injection
  - denial-of-service
  - cloud-native
  - kubernetes
  - supply-chain
vendors:
  - SUSE
  - Rancher
products:
  - Fleet (>= 0.15.0 < 0.15.2)
  - Fleet (>= 0.14.0 < 0.14.6)
  - Fleet (>= 0.13.0 < 0.13.11)
  - Fleet (>= 0.12.0 < 0.12.15)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Trigger continuous repository re-cloning, which increases network traffic and can deplete resources on the management cluster.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-jmf4-m7j9-g72r
---

A high-severity vulnerability, CVE-2026-44937, has been identified in Rancher Fleet, a GitOps at Scale project. When the webhook endpoint of Fleet is configured without a secret, an unauthenticated attacker can forge webhook requests. This allows the attacker to leverage a regex injection vulnerability via unsanitized repository URL components. Exploitation can lead to continuous repository re-cloning, causing significant network traffic and depleting resources on the management cluster, effectively resulting in a Denial of Service. Additionally, attackers with read access to the target Git repository can force a downgrade of running services to any historical revision. This vulnerability impacts Fleet versions prior to v0.15.2, v0.14.6, 0.13.11, and v0.12.15. The issue was reported by Radisauskas Arnoldas from NATO Cyber Security Centre.

## Attack Chain

1. An unauthenticated attacker identifies a Rancher Fleet instance with its webhook endpoint accessible and configured without a shared secret.
2. The attacker crafts a malicious HTTP POST request targeting the Fleet webhook endpoint, such as `/webhook`.
3. Within the request, the attacker injects regular expression patterns into the repository URL components, exploiting the unsanitized input vulnerability (CVE-2026-44937).
4. Fleet receives and processes the forged webhook request, attempting to interpret the malicious regex as a legitimate repository reference.
5. This misinterpretation causes Fleet to initiate continuous, erroneous attempts to re-clone the specified (attacker-controlled or non-existent) repository.
6. The constant re-cloning operations consume excessive network bandwidth and compute resources on the management cluster, leading to a Denial of Service state.
7. If the attacker also has read access to the legitimate target Git repository, they can specify a historical revision via the regex injection to force a service downgrade.

## Impact

This vulnerability allows an unauthenticated attacker to cause significant operational disruption. The primary impact is a Denial of Service (DoS) due to continuous repository re-cloning, which exhausts network resources and compute capacity on the management cluster. This can halt or severely degrade the normal operation of deployed applications and infrastructure managed by Fleet. A secondary impact, conditional on the attacker having read access to the target Git repository, is the ability to force running services to downgrade to any historical revision, potentially introducing older, vulnerable, or non-functional code. The full scope of victims is not specified, but any organization utilizing vulnerable Rancher Fleet configurations is at risk.

## Recommendation

*   Upgrade Rancher Fleet to a patched version (v0.15.2, v0.14.6, 0.13.11, or v0.12.15) to address CVE-2026-44937 immediately.
*   Implement the workaround by ensuring all Fleet webhooks are configured with a shared secret to prevent unauthenticated access.
