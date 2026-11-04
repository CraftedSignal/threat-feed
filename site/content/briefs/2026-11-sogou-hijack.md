---
brief_id: brief-2026-11-04-sogou-hijack
event_id: brief-2026-11-04-sogou-hijack
revision: 1
activity_at: "2026-11-04T13:05:05Z"
title: Tencent Sogou Input Method DNS Hijacking and DarkVigil Deployment
slug: 2026-11-sogou-hijack
description: The threat actor SlippyNunchucks has been attributed to a DNS hijacking operation abusing insecure HTTP communications in Windows versions of the Sogou Input Method to deploy an implant called DarkVigil.
date: "2026-11-04T13:05:05Z"
type: threat
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
tags:
  - supply-chain
  - dns-hijacking
  - dll-sideloading
  - cyber-espionage
references:
  - https://thehackernews.com/2026/11/china-aligned-hackers-hijack-sogou.html
---

The threat actor SlippyNunchucks is conducting a surveillance campaign by hijacking DNS requests within the Sogou Input Method. The attack exploits insecure HTTP communications used by the application to fetch configurations, redirecting requests to actor-controlled staging servers. This process enables the deployment of the DarkVigil (FDMTP) backdoor via DLL sideloading using the legitimate component SGTool.exe. ESET identified this activity, noting that the campaign targets organizations and individuals across Hong Kong, Thailand, Japan, Vietnam, Oman, and Sri Lanka.
