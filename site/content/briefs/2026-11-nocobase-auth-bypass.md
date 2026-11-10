---
brief_id: brief-2026-11-10-nocobase-auth-bypass
event_id: brief-2026-11-10-nocobase-auth-bypass
revision: 1
activity_at: "2026-11-10T02:04:54Z"
title: 'NocoBase plugin-ai: Authorization bypass in getAccessibleAIEmployee (CVE-2026-125397)'
slug: 2026-11-nocobase-auth-bypass
description: NocoBase plugin-ai versions 2.1.0 through 2.2.41 contain an authorization bypass vulnerability allowing authenticated users to access and control unauthorized AI employee configurations and tools.
date: "2026-11-10T02:04:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:nocobase:plugin-ai:*:*:*:*:*:*:*:*
vendors:
  - NocoBase
products:
  - plugin-ai (2.1.0 through 2.2.41)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated users can override role-derived filters by supplying a specific username, allowing unauthorized access to AI employees, their associated tools, permissions, prompts, and configurations.
    confidence_band: high
cves:
  - id: CVE-2026-125397
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125397
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch NocoBase plugin-ai to a version beyond 2.2.41.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability CVE-2026-125397 affects plugin-ai versions 2.1.0 through 2.2.41.
  hunt_leads:
    - lead: Monitor web application access logs for repeated calls to /api/get-ai-employee or /api/dispatch-sub-agent-task by users who do not have assigned AI employee roles.
      technique_id: T1068
      data_needed:
        - Web server access logs
        - Application level audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can use the dispatch-sub-agent-task tool to run ungranted AI employees with their tools and permissions, and get-ai-employee to read their prompts and tool configuration.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin-ai to version 2.2.42 or later.
      owner: IT Operations
      addresses: CVE-2026-125397
      evidence: NocoBase plugin-ai 2.1.0 through 2.2.41 contains an authorization bypass.
---

NocoBase plugin-ai versions 2.1.0 through 2.2.41 are affected by an authorization bypass vulnerability in the `getAccessibleAIEmployee()` function. An authenticated user can bypass role-based access controls by providing a specific username parameter, which overrides the intended filter. This allows the attacker to access AI employees that were not assigned to their role.

## Impact

Successful exploitation allows an authenticated user to perform unauthorized actions, including:
- Accessing unassigned AI employees.
- Executing tools and utilizing permissions associated with restricted AI employees via the `dispatch-sub-agent-task` tool.
- Reading sensitive information, including prompts and tool configurations, via the `get-ai-employee` tool.

## Recommendation

- Upgrade NocoBase plugin-ai to a version later than 2.2.41 to remediate CVE-2026-125397.
- Audit access logs for the `dispatch-sub-agent-task` and `get-ai-employee` API endpoints to identify anomalous usage patterns by unauthorized users.
- Review user roles and permissions within the NocoBase platform to ensure least privilege principles are enforced.
