---
brief_id: brief-2026-11-10-kubeflow-rbac-bypass
event_id: brief-2026-11-10-kubeflow-rbac-bypass
revision: 1
activity_at: "2026-11-10T04:16:16Z"
title: 'Kubeflow Pipelines: RBAC authorization bypass for shared pipelines (CVE-2026-88984)'
slug: 2026-11-kubeflow-rbac-bypass
description: The Kubeflow Pipelines API server in multi-user mode skipped authorization checks for shared pipelines with an empty namespace, allowing authenticated users to modify or delete shared pipelines without required Kubernetes RBAC permissions.
date: "2026-11-10T04:16:16Z"
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
products:
  - go/github.com/kubeflow/pipelines (< 0.0.0-20260420170029-186dd1f3b040)
cves:
  - id: CVE-2026-88984
    epss: 0.0031
    kev_status: "false"
references:
  - https://github.com/kubeflow/pipelines/pull/13288
  - https://github.com/kubeflow/pipelines/security/advisories/GHSA-rjr3-43j3-4q8g
  - https://github.com/advisories/GHSA-ghgh-57qv-h687
---

In multi-user deployments, the Kubeflow Pipelines API server failed to validate authorization for shared or global pipelines that utilize an empty namespace. This defect permitted authenticated users to perform unauthorized write and delete operations on these pipelines. While read-only access remains permitted by design, this vulnerability impacts the integrity and availability of shared pipeline definitions. Single-user deployments do not utilize these multi-user authorization checks.
