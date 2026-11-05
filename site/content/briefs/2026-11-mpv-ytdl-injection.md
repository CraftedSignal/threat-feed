---
brief_id: brief-2026-11-05-mpv-ytdl-injection
event_id: brief-2026-11-05-mpv-ytdl-injection
revision: 1
activity_at: "2026-11-05T18:22:33Z"
title: 'mpv: Playlist injection vulnerability in ytdl_hook (CVE-2026-123095)'
slug: 2026-11-mpv-ytdl-injection
description: The mpv media player contains a playlist injection vulnerability in its bundled ytdl_hook script that allows attackers to bypass security checks and execute arbitrary local files or code.
date: "2026-11-05T18:22:33Z"
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
  validation_status: Source verified, no environment validation required.
cpes:
  - cpe:2.3:a:mpv-player:mpv:*:*:*:*:*:*:*:*
vendors:
  - mpv-player
products:
  - mpv (>= 0.29.0, < 0.42.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.002
    subtechnique_name: Malicious File
    evidence: Attackers controlling a feed or page can bypass url_is_safe() to open file:// or av:// inputs, reading local files or loading shared objects via ladspa for code execution.
    confidence_band: high
cves:
  - id: CVE-2026-123095
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123095
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade mpv to version 0.42.0 or later on all systems.
      owner: IT Operations
      due: 48h
      evidence: mpv 0.29.0 before 0.42.0 contains a playlist injection vulnerability
  hunt_leads:
    - lead: Identify systems running vulnerable mpv versions (0.29.0 to 0.41.0) and inspect their process command line arguments for URLs or file paths containing newline characters or suspicious file:/// and av:// protocols.
      technique_id: T1204.002
      data_needed:
        - Process command line logging
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An attacker can embed newlines in playlist URLs... to open file:// or av:// inputs.
  mitigation_plan:
    - priority: immediate
      action: Upgrade mpv to 0.42.0
      owner: IT Operations
      addresses: CVE-2026-123095
      evidence: mpv 0.29.0 before 0.42.0 contains a playlist injection vulnerability
---

The mpv media player (versions 0.29.0 through 0.41.0) is affected by a playlist injection vulnerability in the bundled `ytdl_hook` script. An attacker can embed newline characters into playlist URLs, causing the script to process unchecked entries. By bypassing the `url_is_safe()` function, an attacker can coerce the player into opening malicious `file://` or `av://` inputs. This can lead to unauthorized local file reading or remote code execution by forcing the player to load malicious shared objects (e.g., via ladspa).

## Impact

Successful exploitation may allow attackers to read arbitrary files from the filesystem of the user running mpv, or achieve remote code execution if the application is configured to load external libraries or malicious plugins.

## Recommendation

* Upgrade to mpv version 0.42.0 or later immediately to include the patched `ytdl_hook` script.
* Audit environments for instances of mpv currently running versions 0.29.0 to 0.41.0.
* In restrictive environments, consider disabling the use of the `ytdl_hook` script if it is not required for media playback operations.
