---
title: SSRF via Improper Domain Validation in LangChain SitemapLoader
slug: 2026-08-langchain-sitemap-ssrf
description: A logic flaw in langchain_community SitemapLoader allows attackers to bypass domain restrictions, enabling Server-Side Request Forgery to access internal network resources and exfiltrate sensitive content.
date: "2026-08-20T23:26:45Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - LangChain
products:
  - langchain_community
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who controls or influences an ingested sitemap can therefore point a nested sitemap entry at an internal address and make the server fetch it.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: The fetched content is parsed and surfaces in the returned Documents, so internal responses are disclosed to the caller rather than merely requested.
    confidence_band: high
cves:
  - id: CVE-2026-72848
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72848
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review ingress points that accept user-provided URLs for sitemap parsing
      owner: SOC
      due: 48h
      evidence: SitemapLoader parses user-supplied sitemaps without sufficient domain validation.
  mitigation_plan:
    - priority: immediate
      action: Restrict egress traffic from application servers to internal IP ranges via firewall or network policies
      owner: IT Operations
      addresses: CVE-2026-72848
      evidence: The vulnerability allows the server to fetch internal resources due to lack of network-level checks.
---

CVE-2026-72848 identifies a critical server-side request forgery (SSRF) vulnerability within the `langchain_community` library, specifically in the `SitemapLoader` class. The vulnerability arises from an incomplete implementation of the `restrict_to_same_domain` security control. While the loader correctly enforces domain restrictions on leaf URL entries, it fails to apply these same checks to nested sitemap elements. 

When processing sitemaps, the loader recursively handles nested sitemap entries by passing them directly to `WebBaseLoader.scrape_all` and subsequently an `aiohttp` GET request. This process occurs without any validation against internal, loopback, or link-local address spaces. An attacker who can influence the sitemap input provided to the application can force the server to fetch internal resources. Because the application then parses and returns the content of these internal requests to the caller, this flaw results in the unauthorized disclosure of sensitive internal data. This vulnerability affects users deploying LangChain components in environments where they rely on `restrict_to_same_domain` for network isolation.

## Impact

Successful exploitation allows for the unauthorized retrieval of internal service data that is otherwise unreachable from the public internet. This includes internal configuration files, metadata services, and internal APIs that are protected by network perimeter defenses but vulnerable to requests originating from within the server environment. This vulnerability poses a high risk to cloud-based deployments and containerized environments where the LangChain application may have implicit access to local network segments or internal cloud metadata endpoints (e.g., 169.254.169.254).

## Recommendation

* Monitor egress traffic from application servers hosting LangChain components to detect unusual HTTP requests to internal IP ranges (RFC1918) or local infrastructure services.
* Implement network-level egress filtering (e.g., via Kubernetes NetworkPolicies or Cloud Security Groups) to restrict the `langchain_community` application's ability to communicate with internal network segments that do not require access.
* Audit applications utilizing `SitemapLoader` to determine if input sitemaps are sourced from untrusted or user-controlled locations.
* Update `langchain_community` to a patched version once released by the vendor to address the logic flaw in `parse_sitemap`.
