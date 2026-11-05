---
brief_id: brief-2026-11-05-sdl-mixer-overflow-4b26a28c
event_id: brief-2026-11-05-sdl-mixer-overflow-4b26a28c
revision: 1
activity_at: "2026-11-05T18:22:27Z"
title: 'SDL_mixer: Stack-based buffer overflow in FetchXLaw (CVE-2026-122329)'
slug: 2026-11-sdl-mixer-overflow-4b26a28c
description: SDL_mixer versions 3.1.2 through 3.2.4 are vulnerable to a stack-based buffer overflow in the FetchXLaw function that can be triggered by malicious AIFF-C files.
date: "2026-11-05T18:22:27Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:libsdl:sdl_mixer:3.1.2:*:*:*:*:*:*:*
  - cpe:2.3:a:libsdl:sdl_mixer:3.2.4:*:*:*:*:*:*:*
vendors:
  - LibSDL
products:
  - SDL_mixer (3.1.2 - 3.2.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply a crafted AIFF-C file that overwrites roughly 1 KB of adjacent stack memory when decoded, causing crashes or potential code execution.
    confidence_band: high
cves:
  - id: CVE-2026-122329
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122329
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify and inventory all software components using SDL_mixer 3.1.2-3.2.4
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects specific versions 3.1.2 through 3.2.4
  hunt_leads:
    - lead: Monitor for abnormal crash events in applications known to process AIFF-C files
      technique_id: T1203
      data_needed:
        - Application crash logs
        - EDR process termination events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Buffer overflow leads to crashes or potential code execution
  mitigation_plan:
    - priority: immediate
      action: Upgrade SDL_mixer to a non-vulnerable version as soon as a patch is released
      owner: IT Operations
      addresses: CVE-2026-122329
      evidence: Vulnerability confirmed in versions 3.1.2 through 3.2.4
---

SDL_mixer versions 3.1.2 through 3.2.4 contain a stack-based buffer overflow in the `FetchXLaw()` function located in `src/decoder_aiff.c`. The vulnerability stems from an incorrect calculation of output offsets when processing A-law or mu-law audio samples within AIFF-C files. Successful exploitation allows an attacker to overwrite approximately 1 KB of adjacent stack memory, which can lead to application crashes or potential arbitrary code execution.

## Impact

Successful exploitation may result in an application crash (Denial of Service) or potential arbitrary code execution depending on the memory layout and the presence of exploit mitigation protections within the host application.

## Recommendation

1. Inventory all applications utilizing SDL_mixer library versions 3.1.2 through 3.2.4.
2. Prioritize upgrading to the latest patched version of SDL_mixer once available.
3. Implement memory safety protections (e.g., stack canaries, DEP, ASLR) at the build or runtime level for applications that process untrusted AIFF-C audio files.
4. Perform input validation or sandboxing for applications that handle AIFF-C files from external, untrusted sources.
