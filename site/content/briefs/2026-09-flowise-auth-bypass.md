---
title: Authorization Bypass in Flowise openai-realtime Endpoints
slug: 2026-09-flowise-auth-bypass
description: Flowise versions prior to 3.1.4 contain an authorization flaw in the openai-realtime endpoint, enabling authenticated users to access and execute tools in unauthorized workspaces via cross-workspace ID manipulation.
date: "2026-09-15T17:43:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:flowiseai:flowise:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - auth-bypass
  - api-security
vendors:
  - n8n GmbH
products:
  - Flowise (< 3.1.4)
cves:
  - id: CVE-2026-91933
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91933
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Flowise to 3.1.4 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-91933 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Flowise 3.1.4
      owner: IT Operations
      addresses: CVE-2026-91933
      evidence: NVD vulnerability mitigation guidance
---

Flowise versions prior to 3.1.4 are susceptible to an authorization bypass vulnerability within the openai-realtime API endpoints. The software fails to properly validate workspace-level authorization when processing requests. This deficiency allows an authenticated user to access ChatFlows and associated tool definitions residing in workspaces they are not authorized to view or manage. By providing an unscoped chatflowid in the API request, an attacker can bypass intended isolation boundaries. This vulnerability allows an attacker to perform GET and POST operations, potentially executing unauthorized tools, causing external side effects, or extracting sensitive information returned by those tools. This flaw represents a significant risk to multi-tenant or multi-workspace deployments where internal data segmentation is a security requirement. Organizations running affected versions should prioritize updating to 3.1.4 or later to remediate the endpoint validation logic.

## Impact

Successful exploitation allows unauthorized access to data and tool execution capabilities within victim workspaces. This may result in the exfiltration of sensitive information, unauthorized modification of backend systems connected via tools, and potential disruption of integrated services. The impact is significant for multi-tenant environments where isolation between workspace data and tool execution is required for compliance and security.

## Recommendation

- Upgrade all Flowise instances to version 3.1.4 or later to enforce workspace-level authorization checks.
- Audit access logs for unauthorized access patterns directed at openai-realtime endpoints.
- Review sensitive tool configurations to ensure they are not accessible to users with minimal workspace privileges until the patch is applied.
