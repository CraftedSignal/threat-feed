---
title: Authorization Bypass in LangGraph SDK Resource Decorators
slug: 2026-10-langgraph-auth-bypass
description: An authorization bypass vulnerability in the LangGraph SDK causes the actions= parameter on resource-scoped decorators to be ignored, potentially allowing authenticated users to perform unauthorized operations.
date: "2026-10-06T00:46:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:langchain:langgraph-sdk:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - cve-2026-104873
  - python
  - langgraph
vendors:
  - LangChain
products:
  - langgraph-sdk (>= 0.1.45, <= 0.4.3)
cves:
  - id: CVE-2026-104873
    epss: 0.00253
references:
  - https://github.com/advisories/GHSA-fvww-7h3r-vfhp
action_plan:
  priority: immediate_escalation
  owners:
    - Application Security
    - Development Team
  immediate_actions:
    - action: Upgrade langgraph-sdk to 0.4.4
      owner: Development Team
      due: 24h
      evidence: Source states patch version 0.4.4
  mitigation_plan:
    - priority: immediate
      action: Manually validate action type inside all resource-scoped authorization handlers
      owner: Development Team
      addresses: CVE-2026-104873
      evidence: Source notes that deployments remain protected if the handler independently enforces action checks
---

The LangGraph SDK (versions 0.1.45 through 0.4.3) contains a critical authorization logic vulnerability identified as CVE-2026-104873. The flaw resides in the SDK's implementation of resource-scoped authorization decorators, specifically `@auth.on.threads`, `@auth.on.assistants`, and `@auth.on.crons`. 

When developers provide an `actions=` argument to these decorators, the SDK fails to filter actions correctly. Instead of binding the handler only to the specified action, it registers the handler for all actions performed on the resource. Because the framework prioritizes these erroneously registered handlers over fallback authorization mechanisms, security checks intended for restricted actions may be bypassed entirely. If the handler logic does not manually validate the requested action against the user's permissions, an authenticated user may execute unauthorized CRUD operations on resources belonging to other users. This vulnerability primarily impacts Python-based deployments utilizing fine-grained action authorization.

## Impact

Deployment of affected versions of `langgraph-sdk` allows for potential privilege escalation and unauthorized access to resources, including threads, assistants, and crons. If a developer assumes that a handler only triggers for specific actions, they may neglect to include action-type validation inside the handler function. In such cases, an authenticated attacker can perform unauthorized read, update, or delete operations on resources they do not own. The severity of the impact depends on the specific logic implemented within the vulnerable decorators.

## Recommendation

1. Upgrade all deployments of `langgraph-sdk` to version 0.4.4 or later immediately.
2. Audit all instances of `@auth.on.threads`, `@auth.on.assistants`, and `@auth.on.crons` to identify usages of the `actions=` parameter.
3. Until patching is completed, verify that all authorization handlers invoked by these decorators explicitly validate the action requested (e.g., check `ctx.action`) to ensure security regardless of the registration scope.
4. Review access logs for anomalous resource operations (e.g., unexpected PUT/DELETE requests) that may indicate exploitation of this authorization flaw.
