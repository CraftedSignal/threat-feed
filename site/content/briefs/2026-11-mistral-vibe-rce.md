---
brief_id: brief-2026-11-05-mistral-vibe-rce
event_id: brief-2026-11-05-mistral-vibe-rce
revision: 1
activity_at: "2026-11-05T00:21:19Z"
title: 'Mistral Vibe: Remote code execution via Git filter drivers (CVE-2026-122134)'
slug: 2026-11-mistral-vibe-rce
description: Mistral Vibe versions before 2.25.7 are vulnerable to remote code execution due to the automatic execution of git commands on untrusted repositories.
date: "2026-11-05T00:21:19Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:mistral:mistral_vibe:*:*:*:*:*:*:*:*
vendors:
  - Mistral AI
products:
  - Mistral Vibe (< 2.25.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: When a user opens a crafted repository, ProjectContextProvider._fetch_git_status runs git status at startup, invoking the filters and executing commands with user privileges before any trust prompt.
    confidence_band: high
cves:
  - id: CVE-2026-122134
    cvss: 8.8
    kev_status: "false"
references:
  - https://www.vulncheck.com/advisories/mistral-vibe-before-2.25.7-code-execution-via-git-filter-drivers
  - https://github.com/mistralai/mistral-vibe/releases/tag/v2.25.7
  - https://sploitus.com/exploit?id=CVE-2026-122134&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Mistral Vibe to version 2.25.7 or later.
      owner: IT Operations
      due: 48h
      evidence: Mistral Vibe before 2.25.7 contains a remote code execution vulnerability.
  hunt_leads:
    - lead: Monitor for git status process executions spawned by Mistral Vibe that invoke external filter drivers.
      technique_id: T1059
      data_needed:
        - Process creation logs (ParentImage, CommandLine)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: ProjectContextProvider._fetch_git_status runs git status at startup, invoking the filters and executing commands.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mistral Vibe to version 2.25.7.
      owner: IT Operations
      addresses: CVE-2026-122134
      evidence: Mistral Vibe before 2.25.7 contains a remote code execution vulnerability.
---

Mistral Vibe prior to version 2.25.7 contains a remote code execution vulnerability (CVE-2026-122134). The vulnerability originates in the ProjectContextProvider component, which automatically executes `git status` when a user opens a repository. An attacker can create a crafted Git repository containing malicious clean or process filter drivers. When a user opens this repository in Mistral Vibe, the application invokes these filters, leading to arbitrary code execution with the user privileges before any user trust prompts occur.

## Impact

Successful exploitation allows for arbitrary code execution on the victim's machine under the context of the user account running Mistral Vibe.

## Recommendation

* Update Mistral Vibe to version 2.25.7 or later to mitigate the vulnerability.
* Implement endpoint policies to restrict the execution of Git processes from non-standard or untrusted directory structures if possible.
* Monitor for child processes spawned by Mistral Vibe or Git processes initiated from unusual project directories.
