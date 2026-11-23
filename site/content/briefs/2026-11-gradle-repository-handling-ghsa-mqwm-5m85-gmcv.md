---
brief_id: brief-2026-11-23-gradle-repository-handling-ghsa-mqwm-5m85-gmcv
event_id: brief-2026-11-23-gradle-repository-handling-ghsa-mqwm-5m85-gmcv
revision: 1
activity_at: "2026-11-23T16:50:00Z"
title: 'Gradle: Dependency resolution repository traversal vulnerability (CVE-2026-22865)'
slug: 2026-11-gradle-repository-handling-ghsa-mqwm-5m85-gmcv
description: Gradle versions prior to 8.14.4 and 9.0-9.3.0 fail to properly disable repositories when encountering transient connection errors, which can be leveraged to resolve dependencies from unauthorized repositories.
date: "2026-11-23T16:50:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment: {}
cpes:
  - cpe:2.3:a:gradle:gradle:*:*:*:*:*:*:*:*
vendors:
  - Gradle
products:
  - gradle-core
cves:
  - id: CVE-2026-22865
    cvss: 7.4
    epss: 0.00158
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-mqwm-5m85-gmcv
  - https://cveawg.mitre.org/api/cve/CVE-2026-22865
---

## Overview
Gradle is a build automation tool that facilitates the retrieval of dependencies from multiple repositories defined in a project. When resolving dependencies, Gradle iterates through configured repositories in a specific order. In affected versions, some exceptions, such as NoHttpResponseException, were not treated as fatal errors and would not cause a repository to be disabled after the maximum number of retries. This behavior allows Gradle to proceed to the next repository in the list.

## Attack Chain
An attacker capable of disrupting a primary repository can force Gradle to continue to the next repository in the defined list. If an attacker controls a subsequent repository, they may leverage this behavior to serve malicious artifacts instead of the intended dependencies. This attack requires the attacker to have control over a repository that is searched after the disrupted repository.

## Impact
This behavior allows an attacker to manipulate the dependency resolution process, potentially leading to the injection of malicious artifacts into a build. The security implications stem from the failure to fail-fast on repository connection errors, preventing intended verification and reproducibility mechanisms.

## Recommendation
- Upgrade to Gradle 8.14.4 or 9.3.0 or later to ensure the build fails correctly when encountering persistent repository connection errors.
- If updating is not immediately feasible, configure dependency verification and strict repository content filtering to ensure only expected dependencies are resolved.
- Audit existing repository declarations in your builds to identify and remove unused or outdated repository endpoints.
