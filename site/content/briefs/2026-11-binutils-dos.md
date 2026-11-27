---
brief_id: brief-2026-11-27-binutils-dos
event_id: brief-2026-11-27-binutils-dos
revision: 1
activity_at: "2026-11-27T08:54:53Z"
title: 'GNU binutils: Denial of Service vulnerability'
slug: 2026-11-binutils-dos
description: A local vulnerability in the GNU binutils software package allows a local attacker to trigger a denial of service condition.
date: "2026-11-27T08:54:53Z"
lastmod: "2026-11-27T08:55:10Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
vendors:
  - GNU
products:
  - binutils
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2241
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0304
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
    - CTI
  enrichment_needed:
    - item: CVE identifiers and affected versions
      owner: CTI
      reason: Required to determine patch applicability and scope of risk.
      evidence: Source provides general vulnerability notification without specific identifiers.
  mitigation_plan:
    - priority: medium_term
      action: Monitor system package repositories and apply updates for binutils once available from the distribution maintainer
      owner: IT Operations
      addresses: GNU binutils local DoS vulnerability
      evidence: BSI security advisory indicates a vulnerability in binutils requiring an update
    - priority: short_term
      action: Monitor vendor and distribution channels for security patch releases
      owner: IT Operations
      addresses: GNU binutils
      evidence: Standard remediation for undisclosed vulnerability reports.
  gaps:
    - The source does not specify a fixed version; local package management tools should be used to track updates
updates:
  - at: "2026-11-27T08:55:10Z"
    level: L2
    summary: added coverage for binutils
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0304
---

## Overview

A local vulnerability exists within the GNU binutils software package that permits an attacker with local access to trigger a denial of service condition on the affected system.

## Impact

Successful exploitation results in a denial of service, rendering the affected system or specific binutils functionality unavailable to legitimate users.

## Recommendation

Systems administrators should monitor for official updates from their respective Linux distribution maintainers and apply them as soon as they become available. Given the local access prerequisite, ensure that only authorized users have access to run binutils utilities on critical systems.
