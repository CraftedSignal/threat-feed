---
brief_id: brief-2026-11-04-docker-security-advisory
event_id: brief-2026-11-04-docker-security-advisory
revision: 1
activity_at: "2026-11-04T22:03:25Z"
title: Docker Buildx and Docker Desktop security updates
slug: 2026-11-docker-security-advisory
description: Docker has addressed a security vulnerability in Docker Buildx where bake filesystem entitlement consent is bypassed when using the --progress=rawjson flag, alongside other general security updates for Docker Desktop.
date: "2026-11-04T22:03:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - vulnerability
  - container-security
  - patch-management
vendors:
  - Docker
products:
  - Docker Buildx (< 0.37.2)
  - Docker Desktop (< 4.98.0)
references:
  - https://cyber.gc.ca/en/alerts-advisories/docker-security-advisory-av26-1123
  - https://docs.docker.com/desktop/release-notes/#4980
  - https://github.com/docker/buildx/security/advisories/GHSA-gwr2-q96m-6682
  - https://docs.docker.com/security/security-announcements/
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Docker Buildx to 0.37.2 or later
      owner: IT Operations
      addresses: GHSA-gwr2-q96m-6682
      evidence: Docker Buildx prior to 0.37.2
    - priority: immediate
      action: Upgrade Docker Desktop to 4.98.0 or later
      owner: IT Operations
      evidence: Docker Desktop prior to 4.98.0
---

Docker has released security updates for Docker Buildx (versions prior to 0.37.2) and Docker Desktop (versions prior to 4.98.0). The Buildx vulnerability involves a bypass of bake filesystem entitlement consent occurring when the --progress=rawjson flag is utilized. Users and administrators should update to the latest versions to ensure these fixes are applied.

## Recommendation

* Update Docker Buildx to version 0.37.2 or later to mitigate the filesystem entitlement bypass.
* Update Docker Desktop to version 4.98.0 or later to ensure all security fixes are applied.
* Review the official Docker security announcements for further details on patches and releases.
