---
brief_id: brief-2026-11-11-active-storage-rce
event_id: brief-2026-11-11-active-storage-rce
revision: 1
activity_at: "2026-11-11T07:27:40Z"
title: 'Ruby on Rails Active Storage: Arbitrary file read and remote code execution (CVE-2026-126186)'
slug: 2026-11-active-storage-rce
description: Ruby on Rails Active Storage is vulnerable to arbitrary file read and potential remote code execution because it uses user-supplied file extensions to determine how external processing tools like FFmpeg and ImageMagick handle uploaded attachments.
date: "2026-11-11T07:27:40Z"
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
  validation_status: Needs environment validation regarding processing tool configuration
cpes:
  - cpe:2.3:a:rubyonrails:rails:*:*:*:*:*:ruby:*:*
tags:
  - rails
  - rce
  - file-read
  - active-storage
vendors:
  - Ruby on Rails
products:
  - Active Storage (< 8.0.5.2, >= 8.1.0.beta1 < 8.1.4.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An FFmpeg built with AviSynth support treats a file with the .avs extension as an AviSynth script and evaluates it.
    confidence_band: high
cves:
  - id: CVE-2026-126186
    cvss: 8.8
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-v924-7rp8-4mxh
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade activestorage to 8.0.5.2 or 8.1.4.1
      owner: IT Operations
      due: 24h
      evidence: Source explicitly names fixed versions as the primary mitigation
    - action: Rotate all application secrets including secret_key_base
      owner: Security Engineering
      due: 48h
      evidence: Source states that upgrading does not undo prior disclosures if AviSynth was enabled
  hunt_leads:
    - lead: Search application logs for unexpected file extensions being passed to external processing binaries like ffmpeg, ffprobe, or convert
      technique_id: T1059
      data_needed:
        - Application audit logs
        - Process execution logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability relies on the tool selecting a decoder based on file extension
  mitigation_plan:
    - priority: immediate
      action: Patch Active Storage to 8.1.4.1 or later
      owner: IT Operations
      addresses: CVE-2026-126186
      evidence: Source provides these specific configuration changes as a temporary workaround
---

Active Storage is vulnerable to arbitrary file read and potential remote code execution due to the insecure handling of temporary files. When processing video or audio attachments, Active Storage creates temporary files that retain the extension provided by the user. External processing tools (FFmpeg, ImageMagick) use these extensions to determine the decoder or delegate if the content itself is ambiguous. An attacker can craft a file with a specific extension (e.g., .avs for AviSynth) to force processing engines to treat the file as a script or library, leading to local file disclosure or RCE within the context of the processing tool.

## Attack Chain

1. An attacker identifies an application using Active Storage that accepts file uploads and performs automatic attachment analysis or preview generation.
2. The attacker crafts a malicious file (e.g., an AviSynth script) and assigns it an extension corresponding to a target processing delegate (e.g., .avs).
3. The attacker uploads the file to the application.
4. Active Storage writes the file to a temporary location while preserving the attacker-provided extension.
5. The application triggers background processing (FFmpeg or ImageMagick) on the file.
6. The processing tool detects the file extension and interprets the content according to the associated decoder or library (e.g., executing the AviSynth script).
7. The process either discloses local sensitive files (if the script reads them) or executes arbitrary native code if a malicious library is loaded.

## Impact

Successful exploitation may result in the unauthorized disclosure of sensitive files readable by the application process (e.g., database credentials, master keys) or remote code execution within the FFmpeg or ImageMagick processing context.

## Recommendation

- Upgrade `activestorage` to version 8.0.5.2 or 8.1.4.1 immediately.
- If an upgrade is not immediately possible, remove `ActiveStorage::Previewer::VideoPreviewer` and the `VideoAnalyzer`/`AudioAnalyzer` from the `config.active_storage` configuration to disable affected processing.
- If the application environment included FFmpeg built with `--enable-avisynth`, consider all application secrets (including `secret_key_base`, database credentials, and service tokens) as potentially compromised; rotate these secrets immediately after patching.
