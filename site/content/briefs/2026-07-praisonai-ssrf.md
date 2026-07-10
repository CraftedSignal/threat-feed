---
title: Unauthenticated Server-Side Request Forgery in PraisonAI Jobs API (CVE-2026-60091)
slug: 2026-07-praisonai-ssrf
description: PraisonAI versions before 4.6.78 contain an unauthenticated server-side request forgery (SSRF) vulnerability, CVE-2026-60091, in the Jobs API `/api/v1/runs` endpoint via the `webhook_url` parameter, allowing attackers to exploit DNS rebinding to access internal services.
date: "2026-07-10T15:25:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - ssrf
  - dns-rebinding
  - praisonai
vendors:
  - MervinPraison
products:
  - PraisonAI (before 4.6.78)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: PraisonAI before 4.6.78 contains an unauthenticated server-side request forgery vulnerability in the Jobs API /api/v1/runs endpoint.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1090
    technique_name: Evade Defenses
    evidence: allowing attackers to use DNS rebinding to reach internal services with a blind SSRF attack.
    confidence_band: high
cves:
  - id: CVE-2026-60091
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60091
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-4w49-gwv8-fpjg
  - https://www.vulncheck.com/advisories/praisonai-before-unauthenticated-ssrf-via-webhook-url
---

An unauthenticated server-side request forgery (SSRF) vulnerability, identified as CVE-2026-60091, exists in PraisonAI versions prior to 4.6.78. This critical flaw resides within the Jobs API `/api/v1/runs` endpoint, specifically impacting the `webhook_url` parameter. Attackers can leverage a timing window where the `webhook_url` is initially validated as an external, legitimate target but then re-resolved to an internal IP address at connection time using DNS rebinding. This allows an external attacker to bypass security controls and force the PraisonAI application to make blind HTTP requests to arbitrary internal network services, potentially leading to unauthorized information disclosure, interaction with internal systems, or further lateral movement within an organization's network.

## Attack Chain

1. The attacker registers a domain (e.g., `attacker.com`) and configures its DNS records with a short Time-To-Live (TTL). Initially, the domain resolves to a legitimate external IP address controlled by the attacker.
2. The attacker sends an unauthenticated POST request to the PraisonAI Jobs API endpoint `/api/v1/runs`, setting the `webhook_url` parameter to their malicious domain (e.g., `http://attacker.com/callback`).
3. During initial validation, PraisonAI performs a DNS lookup for `attacker.com`. At this stage, it resolves to the external IP, passing the validation checks designed to prevent access to internal or private IP ranges.
4. PraisonAI accepts the job and schedules the webhook callback for later execution.
5. Before PraisonAI attempts to connect to the `webhook_url` for the callback, the attacker rapidly updates the DNS record for `attacker.com` to point to an internal IP address (e.g., `192.168.1.10`), which hosts an internal service within the target network.
6. When PraisonAI executes the webhook callback, it performs a new DNS lookup for `attacker.com`. Due to the DNS rebinding, it now resolves to `192.168.1.10`.
7. PraisonAI then makes an HTTP request to `http://192.168.1.10/callback`, initiating a blind server-side request forgery against an internal service.
8. The internal service receives the request, potentially allowing the attacker to gather information about the internal network or interact with other internal systems, albeit blindly.

## Impact

The successful exploitation of CVE-2026-60091 allows an unauthenticated attacker to bypass network segmentation and access internal services from an external position. This blind SSRF can lead to unauthorized information disclosure (C:L) and potentially limited modification of internal data (I:L), as indicated by its CVSS 3.1 score of 7.2. Attackers can use this vulnerability for internal network reconnaissance, identifying other vulnerable services, or indirectly interacting with sensitive internal systems that are not directly exposed to the internet. While direct arbitrary code execution is not implied, the ability to reach internal resources provides a significant foothold for further attack.

## Recommendation

* Patch PraisonAI instances immediately to version 4.6.78 or later to address CVE-2026-60091.
* Implement strict outbound network filtering on the PraisonAI application server to prevent connections to internal IP ranges (RFC1918 addresses) or other unauthorized destinations. (network_connection logs)
* Monitor DNS query logs from the PraisonAI server for suspicious rebinding patterns where a domain initially resolves to an external IP and then quickly changes to an internal IP. (dns_query logs)
