---
title: Gitea Incomplete SSRF Protection in Webhook and Migration Allow-list
slug: 2026-07-gitea-ssrf-bypass
description: An incomplete Server-Side Request Forgery (SSRF) protection in Gitea versions prior to 1.26.3 allows authenticated users to bypass the allow-list in webhook delivery and repository migrations, enabling internal network probing and data exfiltration from sensitive services like cloud metadata endpoints.
date: "2026-07-21T20:30:56Z"
lastmod: "2026-07-21T21:43:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - web-application
  - data-exfiltration
  - vulnerability
  - github
  - gitea
  - authorization-bypass
  - information-disclosure
  - api
  - server-side
  - github-advisory
vendors:
  - Gitea Ltd
  - Gitea
products:
  - Gitea (< 1.26.3)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Scanning
    evidence: An authenticated user can probe and exfiltrate from internal services on CGNAT or non-RFC1918 172.x ranges.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Attackers can read full HTTP response bodies through the webhook history UI.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: content added during the private period becomes available through the fork repository after synchronization.
    confidence_band: high
cves:
  - id: CVE-2026-22874
    cvss: 9.6
    epss: 0.00464
references:
  - https://github.com/advisories/GHSA-2r5c-gw76-rh3w
  - https://pkg.go.dev/net#IP.IsPrivate
  - https://go.dev/blog/subtests
  - https://github.com/go-gitea/gitea/blob/4c37f4dacbac022f7beca75272439331f0368830/modules/hostmatcher/hostmatcher.go#L96-L114
  - https://github.com/go-gitea/gitea/blob/4c37f4dacbac022f7beca75272439331f0368830/services/webhook/deliver.go#L312-L316
  - https://github.com/go-gitea/gitea/blob/4c37f4dacbac022f7beca75272439331f0368830/services/migrations/migrate.go#L522
  - https://github.com/go-gitea/gitea/blob/4c37f4dacbac022f7beca75272439331f0368830/services/webhook/deliver.go#L259-L270
  - https://github.com/go-gitea/gitea/blob/4c37f4dacbac022f7beca75272439331f0368830/templates/repo/settings/webhook/history.tmpl#L75-L85
  - https://github.com/cc-tweaked/CC-Tweaked/blob/3e7ce15ba6d5ab030092850f7e49829b64ba3555/projects/core/src/main/java/dan200/computercraft/core/apis/http/options/AddressPredicate.java#L116-L169
  - https://github.com/advisories/GHSA-wrf9-r3h7-7x5v
  - https://anonymous.4open.science/r/Gitea_PoC-EC93/4_poc_merge_upstream
iocs:
  - type: ip
    value: 168.63.129.16
ioc_counts:
  ip: 1
updates:
  - at: "2026-07-21T21:43:47Z"
    level: L2
    summary: 'merged source coverage: Gitea Fork Synchronization Bypass Exposes Private Repository Content'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-wrf9-r3h7-7x5v
---

A critical vulnerability, CVE-2026-22874, exists in Gitea versions prior to 1.26.3, stemming from an incomplete Server-Side Request Forgery (SSRF) protection mechanism. The allow-list, `MatchBuiltinExternal`, used for webhook delivery and repository migrations, relies on Go's standard library `net.IP.IsPrivate()` function. This function's definition of "private" is too narrow, covering only RFC 1918 and RFC 4193 ranges. As a result, several commonly used internal IP ranges, such as RFC 6598 Carrier-Grade NAT (`100.64.0.0/10`), Azure WireServer (`168.63.129.16`), specific non-RFC1918 `172.x.x.x` ranges, and various IPv6 transition mechanisms (e.g., NAT64 `64:ff9b::/96`, Teredo `2001::/32`), are not blocked. An authenticated user can exploit this to make Gitea initiate HTTP requests to these unblocked internal or cloud metadata endpoints and retrieve the full responses via the webhook history UI. This allows for internal network reconnaissance and sensitive data exfiltration.

## Attack Chain

1. An authenticated user gains access to a Gitea instance.
2. The user navigates to a repository where they have permissions to create or modify a webhook, or initiate a repository migration.
3. The user configures the webhook's target URL (or migration source URL) to point to an IP address within one of the bypassable internal ranges, such as `http://168.63.129.16/metadata` for Azure metadata, or `http://100.64.0.1/internal_api` for a Carrier-Grade NAT network.
4. Gitea attempts to deliver the webhook or perform the migration. Its internal host matcher, `MatchBuiltinExternal`, uses `net.IP.IsPrivate()` to validate the target IP.
5. Due to the narrow definition of `IsPrivate()`, the target IP is incorrectly deemed "public" and the connection is allowed.
6. Gitea's server-side process makes an HTTP request to the specified internal resource, bypassing expected network segmentation.
7. The internal resource responds (e.g., with cloud credentials or internal service configuration), and Gitea captures the full HTTP response, including status, headers, and up to 1 MiB of the body.
8. The authenticated user accesses the webhook history UI for the configured webhook, which displays the captured response, effectively exfiltrating data from the internal network.

## Impact

Successful exploitation of CVE-2026-22874 grants an authenticated attacker the ability to perform extensive Server-Side Request Forgery (SSRF) attacks against the internal network where the Gitea instance is hosted. This can lead to the compromise of sensitive internal systems and data. Specific impacts include accessing cloud metadata endpoints (e.g., AWS IMDS via NAT64, Azure WireServer), probing and exfiltrating data from internal services operating on Carrier-Grade NAT (`100.64.0.0/10`) or non-RFC1918 `172.x.x.x` ranges. The non-blind nature of the SSRF means attackers can read full HTTP response bodies through the webhook history UI, allowing for reconnaissance, sensitive information disclosure, and potential privilege escalation by acquiring credentials or API keys.

## Recommendation

* Upgrade Gitea to version 1.26.3 or later immediately to address CVE-2026-22874.
* Review your Gitea server's outbound network connections for anomalous activity to the IP ranges listed in the IOC table, particularly to cloud metadata service IP addresses.
* Implement network egress filtering on the Gitea server to restrict outbound connections to only necessary and explicitly allowed external destinations, blocking all communication to the internal and cloud metadata IP ranges mentioned in this brief.
