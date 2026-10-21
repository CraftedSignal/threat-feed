---
brief_id: brief-2026-10-21-multicluster-hub-rbac
event_id: brief-2026-10-21-multicluster-hub-rbac
revision: 1
activity_at: "2026-10-21T19:57:15Z"
title: 'multicluster-global-hub-operator-bundle: RBAC privilege escalation (CVE-2026-110744)'
slug: 2026-10-multicluster-hub-rbac
description: The multicluster-global-hub-operator-bundle is configured with overly broad RBAC permissions that grant cluster-wide impersonation of arbitrary users, groups, and service accounts.
date: "2026-10-21T19:57:15Z"
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
  likelihood: roughly even chance
products:
  - multicluster-global-hub-operator-bundle
cves:
  - id: CVE-2026-110744
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110744
---

A flaw was found in multicluster-global-hub-operator-bundle. The operator is configured with overly broad role-based access control (RBAC) permissions that grant cluster-wide impersonation of arbitrary users, groups, and service accounts without restriction. An attacker who compromises the operator or obtains its service account credentials can exploit this flaw to achieve privilege escalation, gaining full administrative control over the cluster.
