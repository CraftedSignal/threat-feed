---
title: Unbound Cache Poisoning Vulnerability
slug: 2026-05-unbound-cache-poisoning
description: A vulnerability in Unbound allows an attacker from an adjacent network to manipulate the cache, potentially leading to domain hijacking.
date: "2026-05-19T12:15:00Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - unbound
  - dns
  - cache poisoning
  - domain hijacking
  - defense-evasion
vendors:
  - NLnet Labs
products:
  - Unbound
affected_os:
  - linux
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2386
rules:
  - title: Detect Unbound DNS Cache Poisoning
    description: Detects suspicious DNS responses that may indicate a cache poisoning attempt against Unbound.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - dns_query
      - linux
rules_count: 1
---

A vulnerability exists within NLnet Labs Unbound DNS resolver that could be exploited by a threat actor positioned on an adjacent network. Successful exploitation allows the attacker to manipulate the DNS cache. This manipulation could redirect users to malicious servers when they attempt to access legitimate domains. This can lead to various malicious outcomes, including credential theft, malware distribution, or disinformation campaigns. This vulnerability poses a significant risk to organizations relying on Unbound for DNS resolution as it can undermine the integrity of their network traffic. Defenders should implement detection and mitigation strategies to protect against potential exploitation.

## Attack Chain

1. The attacker gains access to an adjacent network or performs on-path attack.
2. The attacker sends malicious DNS responses to the Unbound resolver.
3. The malicious responses contain false information about the IP addresses of legitimate domains.
4. Unbound resolver caches the false DNS information.
5. A user on the network queries the Unbound resolver for a legitimate domain.
6. Unbound returns the attacker-controlled IP address from its poisoned cache.
7. The user is redirected to a malicious server controlled by the attacker.
8. The attacker can then perform malicious activities, such as serving malware or stealing credentials.

## Impact

Successful exploitation of this vulnerability can lead to widespread domain hijacking within the affected network. Users attempting to access legitimate websites would be redirected to attacker-controlled servers, potentially exposing them to malware infections or phishing attacks. The impact could range from credential theft and financial loss to the spread of misinformation. The number of affected victims depends on the size of the network relying on the vulnerable Unbound resolver.

## Recommendation

*   Deploy the Sigma rule `Detect Unbound DNS Cache Poisoning` to identify suspicious DNS responses indicative of cache poisoning attempts (log source: `dns_query`).
*   Monitor network traffic for DNS queries resolving to unusual or unexpected IP addresses, especially those originating from the adjacent network (log source: `network_connection`).
