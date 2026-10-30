---
brief_id: brief-2026-10-30-rancher-auth-bypass
event_id: brief-2026-10-30-rancher-auth-bypass
revision: 1
activity_at: "2026-10-30T23:05:08Z"
title: SUSE Rancher Manager authorization bypass (CVE-2026-104623)
slug: 2026-10-rancher-auth-bypass
description: An authorization bypass vulnerability in SUSE Rancher Manager (CVE-2026-104623) allows authenticated users to spawn an unprivileged shell pod in the cattle-system namespace.
date: "2026-10-30T23:05:08Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:suse:rancher_manager:*:*:*:*:*:*:*:*
vendors:
  - SUSE
products:
  - SUSE Rancher Manager (< 2.15.3)
cves:
  - id: CVE-2026-104623
    cvss: 6.3
    kev_status: "false"
references:
  - https://github.com/rancher/rancher/security/advisories/GHSA-8x6f-2v58-x6p7
  - https://sploitus.com/exploit?id=FE9C2F0B-BAA4-509A-8238-5BB7DF6270D8
  - https://sploitus.com/exploit?id=FE9C2F0B-BAA4-509A-8238-5BB7DF6270D8&utm_source=rss&utm_medium=rss
---

CVE-2026-104623 is an authorization bypass vulnerability affecting the `local-cluster-shell` feature in SUSE Rancher Manager. Authenticated Rancher users, including those with minimal global roles and no cluster-level privileges, can bypass authorization checks by using non-standard URL request shapes. This allows the creation of an interactive shell pod (`dashboard-shell-*`) in the `cattle-system` namespace. The issue was addressed in version 2.15.3 by enforcing a `SubjectAccessReview` within the handler.
