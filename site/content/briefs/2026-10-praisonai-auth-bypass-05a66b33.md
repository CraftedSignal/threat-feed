---
brief_id: brief-2026-10-29-praisonai-auth-bypass-05a66b33
event_id: brief-2026-10-29-praisonai-auth-bypass-05a66b33
revision: 1
activity_at: "2026-10-29T19:57:43Z"
title: 'PraisonAI AgentOS: Unauthenticated access to chat route (CVE-2026-57116)'
slug: 2026-10-praisonai-auth-bypass-05a66b33
description: PraisonAI AgentOS versions 4.2.1 through 4.6.58 contain an authentication bypass vulnerability in the FastAPI deployment surface, allowing unauthenticated requests to interact with agents.
date: "2026-10-29T19:57:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
vendors:
  - PraisonAI
products:
  - AgentOS
cves:
  - id: CVE-2026-57116
    cvss: 9.8
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57116
---

PraisonAI AgentOS (versions 4.2.1 to before 4.6.59) features an unauthenticated FastAPI deployment surface. The chat route directly invokes agent.chat(request.message), allowing no-auth or wrong-bearer requests to trigger agents. This potentially allows unauthenticated clients to access agents configured with tools, private context, memory, API integrations, or cost-bearing model calls.
