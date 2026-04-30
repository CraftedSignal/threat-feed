---
title: Langflow IDOR Vulnerability Allows Cross-User Flow Manipulation
slug: 2026-03-langflow-idor
description: Langflow versions 1.5.0 and earlier contain an IDOR vulnerability (CVE-2026-34046) that allows authenticated users to read, modify, and delete flows belonging to other users due to a missing ownership check, potentially exposing sensitive information and enabling unauthorized control over AI agent logic.
date: "2026-03-27T19:36:23Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - idor
  - langflow
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1213
    technique_name: Data from Information Repositories
  - tactic_id: TA0006
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1213
    technique_name: Data from Information Repositories
references:
  - https://github.com/advisories/GHSA-8c4j-f57c-35cf
rules:
  - title: Detect Langflow Unauthorized Flow Access
    description: Detects attempts to access Langflow flows using a flow_id that does not belong to the current user based on HTTP 403 status codes. This suggests a potential IDOR vulnerability exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
  - title: Detect Langflow Flow Modification by Unauthorized User
    description: Detects attempts to modify Langflow flows by users who do not own the flow, based on PATCH requests to the /api/v1/flow/ endpoint combined with a 403 status code, indicative of IDOR exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Langflow, a platform for building AI agents, suffered from an Insecure Direct Object Reference (IDOR) vulnerability affecting versions 1.5.0 and earlier. This flaw, identified as CVE-2026-34046, resided in the `_read_flow` helper function within the `src/backend/base/langflow/api/v1/flows.py` file. The vulnerability arose from a conditional check related to the `AUTO_LOGIN` setting, which inadvertently bypassed ownership validation when authentication was enabled. As a result, any authenticated…
