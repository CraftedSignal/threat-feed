---
brief_id: brief-2026-10-21-php-critical-security-release
event_id: brief-2026-10-21-php-critical-security-release
revision: 9
activity_at: "2026-10-25T04:40:39Z"
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
  - revision: 4
    at: "2026-10-23T09:22:30Z"
    checksum: sha256:515b11256f9c8ad654b6258f38e43fd18fcd0ca6c4381eb685875599395b3e7c
    summary: php version 5.4 <= 8.5.11
    changed_fields:
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - revision: 5
    at: "2026-10-23T11:27:22Z"
    checksum: sha256:29404328b4cfba36b6e26616c18084295f39de88247fa404724a681e919aeb56
    summary: poc_available
    changed_fields:
      - affected_products
      - has_poc
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - revision: 6
    at: "2026-10-23T22:05:51Z"
    checksum: sha256:c510aa1d49b476b2c4148c6d743bf63651eb80c90320069cdee605d424b7df60
    summary: new product
    changed_fields:
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - revision: 7
    at: "2026-10-24T11:14:07Z"
    checksum: sha256:774c9d3916bcf051412796a8416f7525d740dfe8eb1cc1a79f29dcc0c03667a0
    summary: OS ubuntu 22.04; OS ubuntu 24.04
    changed_fields:
      - affected_os
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - revision: 8
    at: "2026-10-24T14:17:37Z"
    checksum: sha256:7dd107fa97dd8817c23b5fa2f6a86c30b41f8dd373badb2827f90eb867ec068e
    summary: new product
    changed_fields:
      - affected_products
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - revision: 9
    at: "2026-10-25T04:40:39Z"
    checksum: sha256:504263cad6de0ff16555ab4928d14f33493e3cd36a3c8c6ea6b780ccd9c1cc64
    summary: new product
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
title: 'PHP: Two critical vulnerabilities ahead of scheduled security release'
slug: 2026-10-php-critical-security-release
description: PHP has announced two critical vulnerabilities rated CVSS v4.0 9.2 and a security release scheduled for 21 October at 14:00 UTC. Exploit details and affected versions are not yet confirmed by PHP.
date: "2026-10-21T07:47:00Z"
lastmod: "2026-10-25T04:40:09Z"
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
cpes:
  - cpe:2.3:a:php:php:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_ape1808_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.8:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.9:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.10:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.11:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.12:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.13:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.14:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.15:-:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.16:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.17:-:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.18:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:11.1.4:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:11.1.5:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:11.1.6:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:11.1.7:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:11.1.8:-:*:*:*:*:*:*
has_poc: true
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
  - PHP (5.4 <= 8.5.11)
  - PHP (5.4 through 8.5.11)
  - PHP (5.4 - 8.5.11)
  - PHP (< 8.5.12, < 8.4.27, < 8.3.36, < 8.2.35)
  - PHP (<= 8.5.11)
affected_os:
  - Ubuntu 22.04
  - Ubuntu 24.04
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of the most severe of these vulnerabilities could allow for unauthenticated remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-109618
    cvss: 9.8
    epss: 0.11841
    kev_status: "false"
  - id: CVE-2026-109619
    cvss: 8.1
    epss: 0.06217
    kev_status: "false"
references:
  - https://www.php.net/archive/2026.php#2026-10-20-1
  - https://cert.europa.eu/publications/security-advisories/2026-018/
  - https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
  - https://gist.github.com/hazcod/71712c0bfe5abf191cbc87245c27fcb8
  - https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
  - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-php-could-allow-for-remote-code-execution_2026-119
  - https://blog.talosintelligence.com/i-had-plans-for-that-second/
  - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - https://security.paloaltonetworks.com/CVE-2026-109618
  - https://www.synology.com/en-us/security/advisory/Synology_SA_26_14
  - https://www.synology.com/en-global/company/news/article/php2shell/Synology%20Statement%20on%20PHP2Shell%20Vulnerabilities
  - https://www.fortiguard.com/psirt/FG-IR-26-186
  - https://www.dfs.ny.gov/industry_guidance/industry_letters/il20261022-cyber-php-patching
  - https://community.citrix.com/techzone-blogs/110_security-updates/protecting-netscaler-management-access-from-php-cve-2026-109618-cve-2026-109619-r1640/
  - https://www.ox.security/blog/php2shell-24-hours-in-99-3-of-measurable-php-instances-are-still-unpatched/
  - https://www.ipa.go.jp/security/security-alert/2026/alert20261022.html
  - https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/
  - https://blog.checkpoint.com/ai-security/php2shell-log4shell-at-ai-speed-a-cisos-perspective/
  - https://www.imperva.com/blog/php2shell-early-attack-activity-through-impervas-lens/
  - https://www.forum-nas.fr/threads/vuln%C3%A9rabilit%C3%A9s-dans-php-php2shell-affectant-plusieurs-produits-qnap.27227/
  - https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-151/
  - https://docs.litespeedtech.com/lsws/changelog/
  - https://www.php.net/archive/2026.php
  - https://ubuntu.com/security/CVE-2026-109618
  - https://www.vulncheck.com/blog/php2shell-vulnerabilities
  - https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/
  - https://support.checkpoint.com/results/sk/sk1000302
  - https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md
  - https://www.qnap.com/en-us/security-advisory/qsa-26-18
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
  - at: "2026-10-23T11:26:43Z"
    level: L2
    summary: poc_available
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - at: "2026-10-23T22:04:31Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - at: "2026-10-24T11:13:34Z"
    level: L1
    summary: OS ubuntu 22.04; OS ubuntu 24.04
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - at: "2026-10-24T14:16:04Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
  - at: "2026-10-25T04:40:09Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/php2shell-cve-2026-109618-109619
---

The PHP security team announced an upcoming release addressing two critical vulnerabilities, each rated CVSS v4.0 9.2. It scheduled the release for 21 October 2026 at 14:00 UTC and said it will disclose technical details, affected versions, and fixed versions with that release. CERT-EU identifies the issues as CVE-2026-109618 and CVE-2026-109619. CERT-EU describes potential remote code execution based on other reporting; PHP has not yet confirmed that attack path. No active exploitation is established in the cited notices.

## Detection opportunity

Hunt for PHP or web-server workers spawning shells, scripting runtimes, discovery commands, or network utilities. The [community Sigma rule for suspicious PHP child processes](https://gist.github.com/hazcod/71712c0bfe5abf191cbc87245c27fcb8) offers a starting point across Linux, macOS, and Windows. It requires process creation telemetry with both parent and child executable paths; use command lines and nearby HTTP requests to investigate matches. Tune known application jobs that intentionally start command-line tools.

This is generic post-execution behavior. A match does not establish exploitation of CVE-2026-109618 or CVE-2026-109619, and execution that stays inside the PHP worker will not match this rule.

## Recommendation

- Identify deployed PHP runtimes and the public applications that depend on them so owners can patch promptly.
- Watch the PHP security release for confirmed affected and fixed versions; test and roll out the relevant updates.
- Treat claims that all PHP versions are affected or that unauthenticated remote code execution is confirmed as provisional until the vendor publishes technical details.
