---
brief_id: brief-2026-11-07-iterm2-nul-byte-injection
event_id: brief-2026-11-07-iterm2-nul-byte-injection
revision: 1
activity_at: "2026-11-07T02:04:29Z"
title: 'iTerm2: NUL-byte argument injection in x-man-page URI handler (CVE-2026-123014)'
slug: 2026-11-iterm2-nul-byte-injection
description: A public proof-of-concept exploit for CVE-2026-123014 targets a NUL-byte argument injection vulnerability in the iTerm2 x-man-page URI handler, enabling arbitrary command execution via maliciously crafted links.
date: "2026-11-07T02:04:29Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
qa_status:
  verdict: pass_with_fixes
  validation_status: Needs environment validation of URI handler invocation patterns.
cpes:
  - cpe:2.3:a:iterm2:iterm2:*:*:*:*:*:*:*:*
vendors:
  - iTerm2
products:
  - iTerm2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: NUL-byte argument injection in iTerm2 x-man-page allows for exploit.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerability allows for arbitrary command execution when a user interacts with a malicious link.
    confidence_band: high
cves:
  - id: CVE-2026-123014
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=F116D130-CE12-5C6D-AC09-899A47FEF251
  - https://sploitus.com/exploit?id=F116D130-CE12-5C6D-AC09-899A47FEF251&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all macOS endpoints with iTerm2 installed via EDR inventory.
      owner: SOC
      due: 24h
      evidence: High severity vulnerability with published PoC requires rapid identification of footprint.
  hunt_leads:
    - lead: Hunt for iTerm2 processes spawned by browser processes or system URI handlers (e.g., launchd) with command line arguments containing x-man-page protocols.
      technique_id: T1203
      data_needed:
        - EDR process creation logs (ParentProcessName, CommandLine)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability specifically targets the x-man-page URI handler.
  mitigation_plan:
    - priority: immediate
      action: Disable x-man-page URI scheme association if possible or restrict its use via organization policy.
      owner: IT Operations
      addresses: CVE-2026-123014
      evidence: Exploitation vector is strictly tied to the x-man-page URI handler.
  gaps:
    - Missing confirmed list of affected version ranges.
---

CVE-2026-123014 is a NUL-byte argument injection vulnerability in the iTerm2 terminal emulator. The flaw exists within the handling of the x-man-page URI scheme. An attacker can trigger arbitrary command execution if a user interacts with a specially crafted URI. A proof-of-concept exploit script written in Shell has been publicly released, increasing the risk of exploitation.

## Impact
The vulnerability allows for remote command execution with the privileges of the iTerm2 application. According to CVSS 4.0 assessment, this vulnerability carries a high severity (8.7) with potential for high impact on system confidentiality and integrity.

## Recommendation
- Inventory systems running iTerm2 to identify potentially vulnerable versions.
- Monitor for official security updates from the iTerm2 project and apply patches immediately upon release.
- Advise users to avoid opening untrusted or unexpected x-man-page:// URI links in browsers or applications.
