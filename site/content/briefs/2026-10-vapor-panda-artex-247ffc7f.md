---
brief_id: brief-2026-10-30-vapor-panda-artex-247ffc7f
event_id: brief-2026-10-30-vapor-panda-artex-247ffc7f
revision: 1
activity_at: "2026-10-30T18:48:44Z"
title: 'Vapor Panda: Automated Cyber Espionage via ARTEX Framework'
slug: 2026-10-vapor-panda-artex-247ffc7f
description: Vapor Panda (formerly VexatiousTemper, overlapping with Earth Estries) is utilizing the AI-powered ARTEX framework to conduct large-scale, concurrent, multi-vector intrusions targeting over 200 global organizations, including foreign ministries, telecommunications, and defense sectors.
date: "2026-10-30T18:48:44Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Vapor Panda
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://thehackernews.com/2026/10/chinese-hackers-use-ai-powered-artex-to.html
  observed_at: "2026-10-17T00:00:00Z"
  confidence: high
source_assessment:
  reliability: D
  credibility: "2"
  rating: D2
  likelihood: likely
tags:
  - cyber-espionage
  - artificial-intelligence
  - vapor-panda
  - artex
vendors:
  - Intapp
products:
  - Intapp Time Server
references:
  - https://thehackernews.com/2026/10/chinese-hackers-use-ai-powered-artex-to.html
---

CrowdStrike has observed the threat actor Vapor Panda using a Go-based, AI-powered penetration testing framework called ARTEX to automate reconnaissance, vulnerability identification, and exploitation. The framework coordinates planner and worker agents to execute attack paths in parallel across web applications, cloud services, and Active Directory. Post-exploitation activities involve the deployment of BLOODALCHEMY, a ShadowPad derivative, followed by credential spraying and reconnaissance. Separately, the threat actor Titan Panda has been observed exploiting hard-coded machine keys in Intapp Time Server.
