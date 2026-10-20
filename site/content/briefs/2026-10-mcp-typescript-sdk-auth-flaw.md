---
brief_id: brief-2026-10-20-mcp-typescript-sdk-auth-flaw
event_id: brief-2026-10-20-mcp-typescript-sdk-auth-flaw
revision: 1
activity_at: "2026-10-20T19:45:28Z"
title: 'Model Context Protocol: MCP TypeScript SDK session isolation vulnerability (CVE-2026-111767)'
slug: 2026-10-mcp-typescript-sdk-auth-flaw
description: The Model Context Protocol (MCP) TypeScript SDK between versions 1.24.0 and 1.32.0 contains an authorization flaw in the InMemoryTaskStore that permits cross-session unauthorized access to tasks.
date: "2026-10-20T19:45:28Z"
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
cpes:
  - cpe:2.3:a:model_context_protocol:typescript_sdk:*:*:*:*:*:*:*:*
vendors:
  - Model Context Protocol
products:
  - MCP TypeScript SDK (1.24.0-1.31.x)
cves:
  - id: CVE-2026-111767
    cvss: 8.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111767
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade MCP TypeScript SDK to version 1.32.0
      owner: IT Operations
      due: 72h
      evidence: Issue has been patched in version 1.32.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade MCP TypeScript SDK to 1.32.0 or later
      owner: IT Operations
      addresses: CVE-2026-111767
      evidence: CVE-2026-111767
---

The MCP TypeScript SDK, utilized for developing Model Context Protocol servers and clients, contains a significant authorization vulnerability (CVE-2026-111767) affecting the experimental tasks feature (taskStore). The flaw exists in versions 1.24.0 through 1.31.x. The implementation of the InMemoryTaskStore fails to validate session ownership when retrieving, listing, or modifying tasks. As a result, in environments where multiple clients or sessions share a single instance of the task store, an attacker can access sensitive task information, list all active tasks, or cancel tasks belonging to other sessions. This failure in multi-tenant isolation poses a risk for any application leveraging the taskStore feature in a shared context. The maintainers have patched this vulnerability in version 1.32.0.

## Impact

Successful exploitation leads to unauthorized information disclosure and disruption of service for legitimate users. In multi-tenant MCP applications, an attacker can enumerate tasks, intercept task-related data from other sessions, and perform denial-of-service by cancelling tasks created by other users. This vulnerability primarily affects applications built on the MCP TypeScript SDK that utilize the experimental taskStore module.

## Recommendation

- Upgrade the MCP TypeScript SDK to version 1.32.0 or later immediately to resolve the session validation flaw.
- If upgrading is not immediately possible, audit applications to determine if the experimental taskStore feature is currently in use and if so, evaluate the risk of shared session state within the environment.
- Review application code that imports the MCP TypeScript SDK to ensure that session isolation logic is enforced at the application layer if relying on the vulnerable taskStore component.
