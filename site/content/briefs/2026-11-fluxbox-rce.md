---
brief_id: brief-2026-11-06-fluxbox-rce
event_id: brief-2026-11-06-fluxbox-rce
revision: 1
activity_at: "2026-11-06T17:26:13Z"
title: 'Fluxbox: OS command injection in RootTheme::reconfigTheme (CVE-2026-123784)'
slug: 2026-11-fluxbox-rce
description: Fluxbox versions 1.3.7 and earlier are vulnerable to OS command injection via crafted style files, allowing arbitrary command execution through unsafe concatenation in the fbsetbg utility.
date: "2026-11-06T17:26:13Z"
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
qa_status:
  verdict: pass
  validation_status: Needs environment validation to identify vulnerable versions
cpes:
  - cpe:2.3:a:fluxbox:fluxbox:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - linux
vendors:
  - Fluxbox
products:
  - Fluxbox (<= 1.3.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Attackers can embed shell metacharacters in background pixmap paths, random directories, or gradient texture text, which are concatenated unescaped into an fbsetbg command run via $SHELL -c when the style loads.
    confidence_band: high
cves:
  - id: CVE-2026-123784
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123784
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all Linux workstations and servers running Fluxbox to identify versions <= 1.3.7
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects Fluxbox versions through 1.3.7
  hunt_leads:
    - lead: Monitor for suspicious process spawning from fbsetbg
      technique_id: T1059.004
      data_needed:
        - Process lineage (e.g., auditd or eBPF)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerable code executes commands via $SHELL -c through the fbsetbg utility
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the patched version of Fluxbox once available
      owner: IT Operations
      addresses: CVE-2026-123784
      evidence: Vulnerability exists in RootTheme::reconfigTheme() in versions through 1.3.7
---

Fluxbox through version 1.3.7 contains an OS command injection vulnerability located within the RootTheme::reconfigTheme() function. The vulnerability is triggered when a user loads a style file containing maliciously crafted background pixmap paths, directory names, or gradient texture strings. These values are unsafely concatenated into an fbsetbg command and executed via a shell, leading to potential arbitrary command execution in the context of the user running Fluxbox.

## Impact

Successful exploitation allows for arbitrary code execution with the privileges of the user running the window manager.

## Recommendation

- Identify all systems running Fluxbox 1.3.7 or earlier within your environment.
- Prioritize updating to the patched version of Fluxbox as soon as it is released by the maintainers.
- Until a patch is applied, restrict access to custom style files and verify the integrity of any style configurations used by users.
