---
brief_id: brief-2026-10-21-php-critical-security-release
event_id: brief-2026-10-21-php-critical-security-release
revision: 3
activity_at: "2026-10-21T20:58:00Z"
revision_history:
  - revision: 2
    at: "2026-10-21T08:26:00Z"
    checksum: sha256:0866246754f90fafb0e195598cedcf6bdeb68ba67050e916a57f7229dd91ada8
    summary: Added a source-backed PHP worker child-process hunt lead with scope and telemetry limits.
    changed_fields:
      - references
      - action_plan
      - body
    source_urls:
      - https://gist.github.com/hazcod/71712c0bfe5abf191cbc87245c27fcb8
  - revision: 3
    at: "2026-10-21T20:58:00Z"
    checksum: sha256:e9e6c2946381963dccfbc36bb0f86c42014f493789dbd7b94d2ad29ea6b4cc5e
    summary: Consolidated duplicate PHP advisory coverage into the verified canonical brief.
    changed_fields:
      - affected_products
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-php-could-allow-for-remote-code-execution_2026-119
      - https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
title: 'PHP: Two critical vulnerabilities ahead of scheduled security release'
slug: 2026-10-php-critical-security-release
description: PHP has announced two critical vulnerabilities rated CVSS v4.0 9.2 and a security release scheduled for 21 October at 14:00 UTC. Exploit details and affected versions are not yet confirmed by PHP.
date: "2026-10-21T07:47:00Z"
lastmod: "2026-10-21T20:58:00Z"
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
  - rce
  - vulnerability
vendors:
  - PHP Group
products:
  - PHP (affected versions not yet confirmed)
  - PHP
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of the most severe of these vulnerabilities could allow for unauthenticated remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-109618
    kev_status: unknown
  - id: CVE-2026-109619
    kev_status: unknown
references:
  - https://www.php.net/archive/2026.php#2026-10-20-1
  - https://cert.europa.eu/publications/security-advisories/2026-018/
  - https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
  - https://gist.github.com/hazcod/71712c0bfe5abf191cbc87245c27fcb8
  - https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
  - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-php-could-allow-for-remote-code-execution_2026-119
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
  hunt_leads:
    - lead: Review process creation events where a PHP or web-server worker starts a shell, scripting runtime, discovery command, or network utility
      technique_id: T1059
      data_needed:
        - Process creation telemetry with parent and child executable paths
        - Child command line and adjacent web request logs for triage
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The linked community Sigma rule detects suspicious child processes from PHP and web workers; this behavior is not specific to either newly announced CVE.
  mitigation_plan:
    - priority: immediate
      action: Review the vendor release at 14:00 UTC and deploy fixed PHP versions when announced
      owner: IT Operations
      addresses: PHP
      evidence: PHP has not yet disclosed the affected or fixed versions; it plans to publish them with the release.
updates:
  - at: "2026-10-21T20:58:00Z"
    level: L2
    summary: Consolidated duplicate PHP advisory coverage into the verified canonical brief.
    sources:
      - huntress
      - ms-isac
    source_urls:
      - https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
      - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-php-could-allow-for-remote-code-execution_2026-119
---

The PHP security team announced an upcoming release addressing two critical vulnerabilities, each rated CVSS v4.0 9.2. It scheduled the release for 21 October 2026 at 14:00 UTC and said it will disclose technical details, affected versions, and fixed versions with that release. CERT-EU identifies the issues as CVE-2026-109618 and CVE-2026-109619. CERT-EU describes potential remote code execution based on other reporting; PHP has not yet confirmed that attack path. No active exploitation is established in the cited notices.

## Detection opportunity

Hunt for PHP or web-server workers spawning shells, scripting runtimes, discovery commands, or network utilities. The [community Sigma rule for suspicious PHP child processes](https://gist.github.com/hazcod/71712c0bfe5abf191cbc87245c27fcb8) offers a starting point across Linux, macOS, and Windows. It requires process creation telemetry with both parent and child executable paths; use command lines and nearby HTTP requests to investigate matches. Tune known application jobs that intentionally start command-line tools.

This is generic post-execution behavior. A match does not establish exploitation of CVE-2026-109618 or CVE-2026-109619, and execution that stays inside the PHP worker will not match this rule.

## Recommendation

- Identify deployed PHP runtimes and the public applications that depend on them so owners can patch promptly.
- Watch the PHP security release for confirmed affected and fixed versions; test and roll out the relevant updates.
- Treat claims that all PHP versions are affected or that unauthenticated remote code execution is confirmed as provisional until the vendor publishes technical details.
