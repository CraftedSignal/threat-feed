---
brief_id: brief-2026-11-04-mistral-vibe-cve
event_id: brief-2026-11-04-mistral-vibe-cve
revision: 2
activity_at: "2026-11-05T00:22:30Z"
revision_history:
  - revision: 2
    at: "2026-11-05T00:22:30Z"
    checksum: sha256:699b1bb39a9846ba897adfafc28ebd8594daeb402872910b83d771fa2d3ce440
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-122135&utm_source=rss&utm_medium=rss
title: 'Mistral Vibe: Untrusted search path remote code execution (CVE-2026-122133)'
slug: 2026-11-mistral-vibe-cve
description: Mistral Vibe before 2.25.5 on Windows contains an untrusted search path vulnerability that allows arbitrary code execution by placing a malicious git.exe in a repository root.
date: "2026-11-04T22:09:42Z"
lastmod: "2026-11-05T00:21:23Z"
type: advisory
claim_state: <nil>
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
qa_status:
  verdict: pass
  validation_status: Needs environment validation of file-path patterns
cpes:
  - cpe:2.3:a:mistral:mistral_vibe:*:*:*:*:*:windows:*:*
  - cpe:2.3:a:mistral:mistral_vibe:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-122135&utm_source=rss&utm_medium=rss
tags:
  - windows
  - rce
  - vulnerability
vendors:
  - Mistral
products:
  - Mistral Vibe (< 2.25.5)
  - Mistral Vibe (< 3.0.3)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    subtechnique_id: T1574.008
    subtechnique_name: Path Interception by Search Order Hijacking
    evidence: Mistral Vibe before 2.25.5 on Windows contains an untrusted search path vulnerability that allows attackers to execute code by placing git.exe in a repository root.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: A crafted repository setting gpg.program and log.showSignature with a signed commit makes git log execute the attacker program at session start
    confidence_band: high
cves:
  - id: CVE-2026-122133
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-122135
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122133
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122135
  - https://sploitus.com/exploit?id=CVE-2026-122135&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Mistral Vibe to version 2.25.5 or later
      owner: IT Operations
      due: 48h
      evidence: Mistral Vibe before 2.25.5 on Windows contains an untrusted search path vulnerability.
    - action: Patch Mistral Vibe to 3.0.3
      owner: IT Operations
      due: 24h
      evidence: Mistral Vibe before 3.0.3 contains a remote code execution vulnerability
  hunt_leads:
    - lead: Identify git.exe files located in non-standard repository subdirectories
      technique_id: T1574.008
      data_needed:
        - File system audit logs
        - EDR file creation events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can lure users into opening a crafted repository so SessionLogger and ProjectContextProvider run the malicious git.exe
    - lead: Identify repositories with suspicious gpg.program configuration
      technique_id: T1059.003
      data_needed:
        - git config --get-all gpg.program
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: A crafted repository setting gpg.program and log.showSignature with a signed commit makes git log execute the attacker program
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mistral Vibe to 2.25.5
      owner: IT Operations
      addresses: CVE-2026-122133
      evidence: Mistral Vibe before 2.25.5 on Windows contains an untrusted search path vulnerability.
    - priority: immediate
      action: Upgrade Mistral Vibe to 3.0.3
      owner: IT Operations
      addresses: CVE-2026-122135
      evidence: Mistral Vibe before 3.0.3 contains a remote code execution vulnerability
updates:
  - at: "2026-11-04T22:09:57Z"
    level: L2
    summary: added coverage for Mistral Vibe (< 3.0.3)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-122135
  - at: "2026-11-05T00:21:23Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-122135&utm_source=rss&utm_medium=rss
---

Mistral Vibe versions before 2.25.5 on Windows are vulnerable to an untrusted search path flaw. The application components SessionLogger and ProjectContextProvider search for git.exe in the repository root upon session startup. An attacker can exploit this by placing a malicious git.exe in the root of a repository; when a user opens this repository, the malicious binary is executed automatically before any trust prompts are displayed.

## Impact
Successful exploitation allows for arbitrary code execution in the context of the user running the Mistral Vibe application.

## Recommendation
- Update Mistral Vibe to version 2.25.5 or later across all Windows workstations.
- Implement file integrity monitoring for repositories to identify unexpected executables in root directories.
- Warn developers to avoid cloning or opening repositories from untrusted or unknown sources.
