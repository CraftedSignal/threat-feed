---
brief_id: brief-2026-11-05-sdl-mixer-overflow
event_id: brief-2026-11-05-sdl-mixer-overflow
revision: 1
activity_at: "2026-11-05T18:22:20Z"
title: 'SDL_mixer: Stack-based buffer overflow in FetchXLaw() (CVE-2026-122328)'
slug: 2026-11-sdl-mixer-overflow
description: SDL_mixer versions 3.1.2 through 3.2.4 contain a stack-based buffer overflow in the FetchXLaw() function that can be triggered by a malformed WAV file, potentially leading to arbitrary code execution.
date: "2026-11-05T18:22:20Z"
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
  validation_status: No Sigma rules generated; vulnerability is in a library and lacks network or process-level indicators in the source.
cpes:
  - cpe:2.3:a:libsdl:sdl_mixer:3.1.2:*:*:*:*:*:*:*
  - cpe:2.3:a:libsdl:sdl_mixer:3.2.4:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
  - media-processing
vendors:
  - Simple DirectMedia Layer
products:
  - SDL_mixer (3.1.2-3.2.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply a crafted WAV file whose doubly-offset float expansion overwrites about 1 KB of adjacent stack memory, causing crashes or potentially code execution.
    confidence_band: high
cves:
  - id: CVE-2026-122328
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122328
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory software dependencies to identify instances of SDL_mixer 3.1.2 through 3.2.4
      owner: IT Operations
      due: 48h
      evidence: Vulnerable versions are explicitly identified in the NVD source.
  hunt_leads:
    - lead: Identify applications loading external WAV files that crash or exhibit abnormal restart behavior
      technique_id: T1203
      data_needed:
        - Application crash logs
        - Process exit codes
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability causes crashes when processing crafted files.
  mitigation_plan:
    - priority: immediate
      action: Update to a patched version of SDL_mixer once available from the vendor
      owner: IT Operations
      addresses: CVE-2026-122328
      evidence: Patching is the required resolution for stack-based overflows in third-party libraries.
---

SDL_mixer versions 3.1.2 through 3.2.4 are vulnerable to a stack-based buffer overflow in the FetchXLaw() function within src/decoder_wav.c. The vulnerability occurs during the decoding of A-law or mu-law encoded WAV files. A crafted input file triggers a doubly-offset float expansion that overwrites approximately 1 KB of adjacent stack memory. Successful exploitation can result in application crashes or arbitrary code execution.

## Impact

The vulnerability allows an attacker to cause memory corruption, leading to application instability (crashes) or potential remote code execution depending on the context in which the affected application processes the malicious media file.

## Recommendation

* Inventory applications utilizing SDL_mixer library versions 3.1.2 through 3.2.4.
* Monitor for applications that load media files from untrusted sources and link against these vulnerable library versions.
* Patch or update to a non-vulnerable version of SDL_mixer as soon as one is made available by the vendor.
