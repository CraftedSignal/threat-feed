---
brief_id: brief-2026-10-29-langgraph-auth-bypass-894be0bf
event_id: brief-2026-10-29-langgraph-auth-bypass-894be0bf
revision: 1
activity_at: "2026-10-29T00:12:14Z"
title: 'LangChain langgraph-api: Store authorization bypass (CVE-2026-118668)'
slug: 2026-10-langgraph-auth-bypass-894be0bf
description: A vulnerability in langgraph-api custom authentication for JavaScript and TypeScript handlers allows authenticated users to access Store data outside their assigned namespace via failed authorization rewriting.
date: "2026-10-29T00:12:14Z"
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
  validation_status: Confirmed against source advisory
cpes:
  - cpe:2.3:a:langchain:langgraph-api:*:*:*:*:*:*:*:*
vendors:
  - LangChain
products:
  - langgraph-api (< 0.15.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: In affected deployments, an authenticated user may be able to access Store data outside their authorized namespace.
    confidence_band: high
cves:
  - id: CVE-2026-118668
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-4hm6-w6qq-w73v
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch langgraph-api to version 0.15.0 or later
      owner: IT Operations
      due: 48h
      evidence: The issue is fixed in langgraph-api version 0.15.0.
  hunt_leads:
    - lead: Identify and audit all LangGraph custom JavaScript or TypeScript authentication handlers that use namespace rewriting logic.
      technique_id: T1068
      data_needed:
        - Custom authentication handler code
        - LangGraph deployment configuration
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Deployments that cannot upgrade immediately should change JavaScript or TypeScript Store authorization handlers to reject requests for unauthorized namespaces.
  mitigation_plan:
    - priority: immediate
      action: Update custom authentication logic to reject requests for unauthorized namespaces instead of rewriting.
      owner: IT Operations
      addresses: CVE-2026-118668
      evidence: Deployments that cannot upgrade immediately should change JavaScript or TypeScript Store authorization handlers to reject requests for unauthorized namespaces rather than relying on namespace rewriting.
---

The LangChain `langgraph-api` package contains an authorization vulnerability (CVE-2026-118668) affecting deployments that utilize JavaScript or TypeScript custom authentication handlers. If the handler is configured to rewrite namespaces to restrict user access, the runtime fails to correctly apply these modifications. This allows an authenticated user to perform unauthorized read, search, modify, or delete operations on Store data residing in other users' namespaces.

The issue does not affect Python-based handlers or JavaScript/TypeScript handlers that reject (rather than rewrite) unauthorized requests.

## Impact
Successful exploitation allows an authenticated user to bypass logical access controls within the LangGraph Store. This results in unauthorized access, modification, or destruction of data belonging to other users. No administrative privileges or user interaction are required to exploit the flaw.

## Recommendation
- Upgrade `langgraph-api` to version 0.15.0 or later immediately.
- For environments unable to patch, modify JavaScript/TypeScript authorization handlers to explicitly reject requests for unauthorized namespaces, rather than relying on internal namespace rewriting. 
- Conduct a review of all Store-related authorization logic to ensure requests are rejected upon unauthorized access attempts.
