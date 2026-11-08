---
brief_id: brief-2026-11-08-craft-cms-rce
event_id: brief-2026-11-08-craft-cms-rce
revision: 1
activity_at: "2026-11-08T15:30:06Z"
title: 'Craft CMS: Remote code execution via app/render-elements (CVE-2026-124430)'
slug: 2026-11-craft-cms-rce
description: Craft CMS versions from 5.10.0 before 5.11.2 contain a remote code execution vulnerability that allows non-administrator control panel users to execute OS commands.
date: "2026-11-08T15:30:06Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Craft CMS (5.10.0 <= version < 5.11.2)
cves:
  - id: CVE-2026-124430
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124430
---

Craft CMS versions from 5.10.0 before 5.11.2 contain a remote code execution vulnerability. Non-administrator control panel users can obtain HMAC-signed Twig templates via the `app/render-elements` endpoint. By submitting the signed templated `returnUrl` as a login redirect parameter, attackers can trigger unsandboxed `renderObjectTemplate()` evaluation, resulting in OS command execution as the PHP worker.
