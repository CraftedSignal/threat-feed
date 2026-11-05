---
brief_id: brief-2026-11-04-sogou-hijack
event_id: brief-2026-11-04-sogou-hijack
revision: 2
activity_at: "2026-11-05T02:30:04Z"
revision_history:
  - revision: 2
    at: "2026-11-05T02:30:04Z"
    checksum: sha256:3d1d08371996526821509af58456ae9a6e12fc796b3dff310fdbc06a9a836a06
    summary: added CVE-2026-120422; OS windows
    changed_fields:
      - affected_os
      - affected_vendors
      - claim_state
      - cpes
      - cves
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.welivesecurity.com/en/eset-research/slippynunchucks-hijacks-sogou-input-methods-brand-promotion-mechanism-to-distribute-malware/
title: Tencent Sogou Input Method DNS Hijacking and DarkVigil Deployment
slug: 2026-11-sogou-hijack
description: The threat actor SlippyNunchucks has been attributed to a DNS hijacking operation abusing insecure HTTP communications in Windows versions of the Sogou Input Method to deploy an implant called DarkVigil.
date: "2026-11-04T13:05:05Z"
lastmod: "2026-11-05T02:27:37Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
actors:
  - SlippyNunchucks
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://thehackernews.com/2026/11/china-aligned-hackers-hijack-sogou.html
  observed_at: "2026-07-01T00:00:00Z"
  confidence: high
source_assessment:
  reliability: D
  credibility: "2"
  rating: D2
  likelihood: likely
cpes:
  - cpe:2.3:o:tencent:windows:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - dns-hijacking
  - dll-sideloading
  - cyber-espionage
vendors:
  - Tencent
affected_os:
  - Windows
cves:
  - id: CVE-2026-120422
    kev_status: "false"
references:
  - https://thehackernews.com/2026/11/china-aligned-hackers-hijack-sogou.html
  - https://www.welivesecurity.com/en/eset-research/slippynunchucks-hijacks-sogou-input-methods-brand-promotion-mechanism-to-distribute-malware/
iocs:
  - type: domain
    value: config.pinyin.sogou.com
ioc_counts:
  domain: 1
updates:
  - at: "2026-11-05T02:27:37Z"
    level: L2
    summary: added CVE-2026-120422; OS windows
    sources:
      - eset
    source_urls:
      - https://www.welivesecurity.com/en/eset-research/slippynunchucks-hijacks-sogou-input-methods-brand-promotion-mechanism-to-distribute-malware/
---

The threat actor SlippyNunchucks is conducting a surveillance campaign by hijacking DNS requests within the Sogou Input Method. The attack exploits insecure HTTP communications used by the application to fetch configurations, redirecting requests to actor-controlled staging servers. This process enables the deployment of the DarkVigil (FDMTP) backdoor via DLL sideloading using the legitimate component SGTool.exe. ESET identified this activity, noting that the campaign targets organizations and individuals across Hong Kong, Thailand, Japan, Vietnam, Oman, and Sri Lanka.
