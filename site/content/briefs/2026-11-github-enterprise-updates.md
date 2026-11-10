---
brief_id: brief-2026-11-04-github-enterprise-updates
event_id: brief-2026-11-04-github-enterprise-updates
revision: 2
activity_at: "2026-11-10T20:02:41Z"
revision_history:
  - revision: 2
    at: "2026-11-10T20:02:41Z"
    checksum: sha256:45f79e6d2954a7df4af37e9f20abc2c63f9db647bc7c948727a38d3f2db8701b
    summary: added coverage for Git (2.50-2.56) +1 products
    changed_fields:
      - action_plan
      - affected_products
      - affected_vendors
      - content
      - cpes
      - cves
      - lastmod
      - priority_score
      - priority_signals
      - references
      - severity
      - summary
      - title
      - ttps
      - updates
    source_urls:
      - https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html
title: 'Git: Multiple vulnerabilities allowing remote code execution and denial of service'
slug: 2026-11-github-enterprise-updates
description: Multiple vulnerabilities in Git, including an integer truncation flaw (CVE-2026-111760), enable attackers to achieve remote code execution or denial of service via malicious repositories during recursive clones or merge operations.
date: "2026-11-04T21:09:06Z"
lastmod: "2026-11-10T20:01:47Z"
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
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:git:git:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - enterprise-server
  - security-update
vendors:
  - GitHub
  - Git
products:
  - Enterprise Server (3.19.0 < 3.19.14)
  - Enterprise Server (3.20.0 < 3.20.10)
  - Enterprise Server (3.21.0 < 3.21.8)
  - Enterprise Server (3.22.0 < 3.22.3)
  - Git (2.50-2.56)
  - GitHub Enterprise Server (3.19-3.22)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A flaw in Git can let a malicious repository run an attacker's code on a computer that clones it recursively.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.002
    technique_name: Malicious File
    evidence: This lets an attacker replace a submodule's .git file with a symbolic link to a folder holding malicious hooks or configuration.
    confidence_band: high
cves:
  - id: CVE-2026-105437
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-111760
    kev_status: unknown
references:
  - https://cyber.gc.ca/en/alerts-advisories/github-security-advisory-av26-1126
  - https://docs.github.com/en/enterprise-server@3.19/admin/release-notes
  - https://docs.github.com/en/enterprise-server@3.20/admin/release-notes
  - https://docs.github.com/en/enterprise-server@3.21/admin/release-notes
  - https://docs.github.com/en/enterprise-server@3.22/admin/release-notes
  - https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Git and GitHub Enterprise Server to the versions specified in the Overview.
      owner: IT Operations
      due: 48h
      evidence: The Git project fixed it this week in Git 2.56.1, with matching fixes for the 2.50 through 2.55 series.
  hunt_leads:
    - lead: Identify repositories with unusually long file paths or suspicious .git configurations in submodules.
      technique_id: T1565
      data_needed:
        - Git repository metadata
        - File system change logs on development endpoints
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An extremely long path in a repository can pass Git's safety check, but Git then writes it to disk under a shorter name that an attacker can set to .git.
  mitigation_plan:
    - priority: immediate
      action: Upgrade GitHub Enterprise Server to at least versions 3.19.14, 3.20.10, 3.21.8, or 3.22.3.
      owner: IT Operations
      addresses: GitHub Enterprise Server security updates
      evidence: As of November 3, 2026, GitHub is affected by vulnerabilities in the following product.
    - priority: immediate
      action: Set conflict-marker-size=7 in repository info/attributes for servers unable to patch immediately.
      owner: IT Operations
      addresses: CVE-2026-105437
      evidence: As a workaround for this flaw, servers that cannot upgrade yet can add conflict-marker-size=7 to each repository's info/attributes file.
updates:
  - at: "2026-11-10T20:01:47Z"
    level: L2
    summary: added coverage for Git (2.50-2.56) +1 products
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/11/git-patches-flaw-that-lets-malicious.html
---

The Git project has released updates addressing six security vulnerabilities affecting Git versions 2.50 through 2.55 and 2.56. The most critical issue, CVE-2026-111760, involves integer truncation during index handling, which can allow an attacker to write files outside of the intended directory structure and execute arbitrary code via malicious Git hooks. Other vulnerabilities include path traversal during clones, memory corruption during tag merges, and integer overflows leading to crashes.

## Impact

Successful exploitation of these vulnerabilities can lead to remote code execution (RCE) on developer workstations or build servers that process malicious repositories, as well as denial of service (DoS) conditions for Git hosting infrastructure.

## Recommendation

- Update all Git installations to the patched versions: 2.50.2, 2.51.3, 2.52.1, 2.53.1, 2.54.1, 2.55.1, or 2.56.1.
- Upgrade GitHub Enterprise Server to version 3.19.15, 3.20.11, 3.21.9, or 3.22.4.
- Implement temporary mitigations for CVE-2026-105437 by adding `conflict-marker-size=7` to repository `info/attributes` files or disabling automated merge checks for untrusted repositories.
- Enforce strict policies against recursive cloning and processing of untrusted repositories, patches, or fast-import streams.
