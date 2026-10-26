---
brief_id: brief-2026-10-23-fortinet-security-updates
event_id: brief-2026-10-23-fortinet-security-updates
revision: 2
activity_at: "2026-10-26T11:55:56Z"
revision_history:
  - revision: 2
    at: "2026-10-26T11:55:56Z"
    checksum: sha256:b3c6a9a7854f9fbc795844dd85ba24cae05ea9ebd55e3946a57191c24dfb6b6b
    summary: new product
    changed_fields:
      - affected_products
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/fortinet-ai-found-flaws-hardening-release-oct-2026
title: 'Fortinet: Multiple product security updates'
slug: 2026-10-fortinet-security-updates
description: Fortinet has released security hardening updates for FortiAnalyzer, FortiAuthenticator, FortiMail, FortiManager, and FortiOS to address multiple vulnerabilities.
date: "2026-10-23T15:00:39Z"
lastmod: "2026-10-26T11:55:24Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Advisory reviewed; patch management required.
tags:
  - vulnerability-management
  - network-security
  - informational
  - product-news
vendors:
  - Fortinet
products:
  - FortiAnalyzer (< 8.0.2, < 7.6.8, < 7.4.12, < 7.2.13)
  - FortiAuthenticator (< 8.0.4, < 6.6.11)
  - FortiMail (< 8.0.2, < 7.6.7, < 7.4.9, 7.2 branch requires upgrade to 7.4+)
  - FortiManager (< 8.0.2, < 7.6.8, < 7.4.12, < 7.2.13)
  - FortiOS (< 8.0.2, < 7.6.8, < 7.4.13, < 7.2.14)
  - FortiOS (8.0.0–8.0.1, 7.6.0–7.6.7, 7.4.0–7.4.12, 7.2.0–7.2.13)
  - FortiManager (8.0.0–8.0.1, 7.6.0–7.6.7, 7.4.0–7.4.11, 7.2.0–7.2.12)
  - FortiAnalyzer (8.0.0–8.0.1, 7.6.0–7.6.7, 7.4.0–7.4.11, 7.2.0–7.2.12)
  - FortiMail (8.0.0–8.0.1, 7.6.0–7.6.6, 7.4.0–7.4.8, 7.2.0–7.2.9)
  - FortiAuthenticator (8.0.0–8.0.3, 6.6.0–6.6.10)
references:
  - https://cyber.gc.ca/en/alerts-advisories/fortinet-security-advisory-av26-1081
  - https://www.fortinet.com/blog/ciso-collective/fortinet-releases-security-hardening-release-for-multiple-products
  - https://pwn.watch/i/fortinet-ai-found-flaws-hardening-release-oct-2026
  - https://digital.nhs.uk/cyber-alerts/2026/cc-4879
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Fortinet appliances to the specified secure firmware versions
      owner: IT Operations
      addresses: FortiAnalyzer, FortiAuthenticator, FortiMail, FortiManager, FortiOS
      evidence: Fortinet security hardening release guidance
updates:
  - at: "2026-10-26T11:55:24Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/fortinet-ai-found-flaws-hardening-release-oct-2026
---

Fortinet has released security updates for multiple products to address vulnerabilities across their infrastructure stack. Administrators are directed to the official Fortinet PSIRT advisories to identify specific CVEs and impact details for their environment and to apply the required patches.

## Recommendation
- Audit all internet-facing and internal Fortinet appliances to determine current firmware versions.
- Patch FortiAnalyzer, FortiAuthenticator, FortiMail, FortiManager, and FortiOS to the minimum versions listed in the affected products section.
- Review the Fortinet PSIRT advisories linked in the reference section for specific vulnerability impact and risk assessment.
