---
brief_id: brief-2026-10-30-pillow-oob-write
event_id: brief-2026-10-30-pillow-oob-write
revision: 1
activity_at: "2026-10-30T00:25:26Z"
title: 'Pillow: Native out-of-bounds write via multi-frame image mode transition (CVE-2026-96639)'
slug: 2026-10-pillow-oob-write
description: Pillow multi-frame loaders retain stale native image storage across mode transitions, leading to out-of-bounds writes and potential remote command execution when processing crafted MPO, PSD, DCX, or MIC files.
date: "2026-10-30T00:25:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: verified against GHSA
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - memory-corruption
  - pillow
products:
  - Pillow (>= 11.0.0, < 13.0.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: I also demonstrated command execution in matching Python/Pillow runtime profiles through Pillow's documented ImageSequence.Iterator + frame.load() path.
    confidence_band: high
cves:
  - id: CVE-2026-96639
    cvss: 9.8
    epss: 0.00659
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-v9pv-5gc8-w2m6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96639
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Pillow to 13.0.0 or later on all systems.
      owner: IT Operations
      due: 24h
      evidence: Pillow >= 11.0.0, < 13.0.0 is vulnerable.
  hunt_leads:
    - lead: Identify applications running Pillow versions 11.x or 12.x in the production environment.
      technique_id: T1203
      data_needed:
        - Software inventory reports
        - Dependency manifests (requirements.txt, Pipfile.lock)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Pillow (>= 11.0.0, < 13.0.0) is the affected range.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Pillow to 13.0.0.
      owner: IT Operations
      addresses: CVE-2026-96639
      evidence: GHSA-v9pv-5gc8-w2m6
---

Pillow (versions 11.0.0 through 12.3.0) contains a vulnerability where multi-frame image loaders do not properly validate retained native `ImagingCore` storage when a frame transition changes the image mode or dimensions. If frame 0 allocates a narrow buffer (e.g., mode `L`) and a subsequent frame requires a wider mode (e.g., `RGB`, `CMYK`), the decoder may write data into the stale, undersized buffer. This results in native out-of-bounds memory corruption, potential application crashes, and arbitrary command execution.

## Attack Chain
1. Attacker crafts a multi-frame image file (PSD, MPO, DCX, or MIC) containing at least two frames.
2. Frame 0 is set to a narrow pixel mode (e.g., `L`) to trigger allocation of native storage.
3. Frame 1 is crafted with a wider pixel mode (e.g., `RGB` or `CMYK`) and the same dimensions as Frame 0.
4. The victim application calls `Image.open()` on the crafted file.
5. The application iterates to the second frame using `ImageSequence.Iterator`.
6. The application invokes `frame.load()` on the second frame.
7. Pillow reuses the native storage buffer from Frame 0 without revalidating the mode/size requirements.
8. The decoder performs an out-of-bounds write to the native buffer, leading to memory corruption or code execution.

## Impact
The vulnerability allows for denial-of-service via process crashes. In the MPO/JPEG path, exploitation can lead to native out-of-bounds writes and arbitrary command execution under the context of the user running the Python process. The attack is achievable via a single unauthenticated HTTP request in web applications that process uploaded images using affected Pillow versions.

## Recommendation
- Update Pillow to version 13.0.0 or later immediately.
- Audit all internal and public-facing services for the use of `PIL.Image` and `PIL.ImageSequence` to process user-supplied image files.
- Implement strict input validation or file-type filtering for image uploads to block potentially malicious multi-frame formats if an immediate upgrade is not feasible.
- Restrict the execution environment of image processing services to minimize the impact of potential command execution (e.g., using containers with minimal privileges, no shells, and restricted file system access).
