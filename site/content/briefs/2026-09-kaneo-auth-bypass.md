---
title: Authorization Bypass in Kaneo Bulk Task API
slug: 2026-09-kaneo-auth-bypass
description: Authenticated users with restricted roles in Kaneo versions 2.3.12 through 2.12.1 can perform unauthorized task modifications or deletions by exploiting a missing permission check in the bulk task API endpoint.
date: "2026-09-22T22:40:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kaneo:kaneo:*:*:*:*:*:*:*:*
vendors:
  - Kaneo
products:
  - Kaneo (2.3.12 - 2.12.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The bulk task endpoint Omissions workspace permission checks, allowing authenticated workspace members with viewer or member roles to delete and modify tasks beyond their assigned permissions.
    confidence_band: high
cves:
  - id: CVE-2026-63104
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63104
rules:
  - title: Detects CVE-2026-63104 Exploitation - Unauthorized PATCH to Bulk Task API
    description: Detects HTTP PATCH requests to the /api/task/bulk endpoint, which is associated with unauthorized task modifications in vulnerable versions of Kaneo.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Kaneo to 2.12.2 or later
      owner: IT Operations
      due: 48h
      evidence: Source documentation for CVE-2026-63104
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to /api/task/bulk if immediate patching is not possible
      owner: IT Operations
      addresses: CVE-2026-63104
      evidence: Vulnerability exists in the API endpoint implementation
---

Kaneo versions 2.3.12 through 2.12.1 are affected by a critical missing authorization vulnerability, tracked as CVE-2026-63104. The flaw resides within the PATCH /api/task/bulk endpoint, which fails to enforce granular role-based access control (RBAC) checks. While standard task management endpoints correctly validate user permissions based on assigned roles, the bulk endpoint only verifies general workspace membership. This oversight allows workspace members and viewers, who should have restricted access, to execute unauthorized PATCH operations. Exploitation enables these users to modify critical task attributes - including status, priority, assignee, due dates, and labels - or perform bulk deletions of tasks across the entire workspace. This vulnerability represents a significant risk to project integrity and data availability for organizations relying on Kaneo for task management, as it grants restricted users administrative-level control over task lifecycle operations.

## Impact

Successful exploitation allows low-privileged users to disrupt project workflows, delete historical task data, and modify sensitive task assignments without authorization. This could result in widespread data loss, project management chaos, and violation of internal security policies regarding task modification privileges. Organizations using Kaneo to track critical business processes or sensitive project roadmaps are at high risk of unauthorized data manipulation.

## Recommendation

- Upgrade Kaneo instances to version 2.12.2 or later immediately to resolve the missing authorization check in the API.
- Review web access logs for anomalous PATCH requests to the /api/task/bulk endpoint, specifically monitoring for high volumes of requests originating from users with 'viewer' or 'member' roles.
- Implement request-rate limiting and access controls at the API gateway layer to restrict access to the /api/task/bulk endpoint to authorized project managers or administrators until the patch is applied.
