---
brief_id: brief-2026-10-21-php-critical-security-release
event_id: brief-2026-10-21-php-critical-security-release
revision: 1
activity_at: "2026-10-21T07:47:00Z"
title: 'PHP: Two critical vulnerabilities ahead of scheduled security release'
slug: 2026-10-php-critical-security-release
description: PHP has announced two critical vulnerabilities rated CVSS v4.0 9.2 and a security release scheduled for 21 October at 14:00 UTC. Exploit details and affected versions are not yet confirmed by PHP.
date: "2026-10-21T07:47:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
qa_status:
  verdict: pass
tags:
  - php
  - security-release
vendors:
  - PHP Group
products:
  - PHP (affected versions not yet confirmed)
cves:
  - id: CVE-2026-109618
    kev_status: unknown
  - id: CVE-2026-109619
    kev_status: unknown
references:
  - https://www.php.net/archive/2026.php#2026-10-20-1
  - https://cert.europa.eu/publications/security-advisories/2026-018/
  - https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory PHP runtimes and identify internet-facing applications before the scheduled release
      owner: IT Operations
      due: 24h
      evidence: The PHP security team advises users to prepare to upgrade when its security release becomes available.
  mitigation_plan:
    - priority: immediate
      action: Review the vendor release at 14:00 UTC and deploy fixed PHP versions when announced
      owner: IT Operations
      addresses: PHP
      evidence: PHP has not yet disclosed the affected or fixed versions; it plans to publish them with the release.
---

The PHP security team announced an upcoming release addressing two critical vulnerabilities, each rated CVSS v4.0 9.2. It scheduled the release for 21 October 2026 at 14:00 UTC and said it will disclose technical details, affected versions, and fixed versions with that release. CERT-EU identifies the issues as CVE-2026-109618 and CVE-2026-109619. CERT-EU describes potential remote code execution based on other reporting; PHP has not yet confirmed that attack path. No active exploitation is established in the cited notices.

## Recommendation

- Identify deployed PHP runtimes and the public applications that depend on them so owners can patch promptly.
- Watch the PHP security release for confirmed affected and fixed versions; test and roll out the relevant updates.
- Treat claims that all PHP versions are affected or that unauthenticated remote code execution is confirmed as provisional until the vendor publishes technical details.
