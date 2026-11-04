---
brief_id: brief-2026-11-04-adonisjs-bodyparser-traversal
event_id: brief-2026-11-04-adonisjs-bodyparser-traversal
revision: 1
activity_at: "2026-11-04T07:58:22Z"
title: 'AdonisJS Bodyparser: Arbitrary file write via path traversal (CVE-2026-21440)'
slug: 2026-11-adonisjs-bodyparser-traversal
description: An unauthenticated remote path traversal vulnerability in @adonisjs/bodyparser (CVE-2026-21440) allows attackers to write arbitrary files to the filesystem via malicious multipart/form-data filenames.
date: "2026-11-04T07:58:22Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:adonisjs:adonisjs_bodyparser:*:*:*:*:*:*:*:*
vendors:
  - Adonisjs
products:
  - '@adonisjs/bodyparser (<= 10.1.1, 11.0.0-next.1 - 11.0.0-next.5)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated remote path traversal in @adonisjs/bodyparser allows arbitrary file write.
    confidence_band: high
cves:
  - id: CVE-2026-21440
    epss: 0.01034
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21440
  - https://sploitus.com/exploit?id=AC4899CD-71F0-5B81-BBC2-DFE8E7F98942
  - https://sploitus.com/exploit?id=AC4899CD-71F0-5B81-BBC2-DFE8E7F98942&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-21440 Exploitation Attempt
    description: Detects potential path traversal attempts in multipart file upload requests targeting AdonisJS applications by monitoring for directory traversal sequences in the filename parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @adonisjs/bodyparser to 10.1.2 or 11.0.0-next.6
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-21440 vendor fix recommendation
  hunt_leads:
    - lead: Search web server access logs for POST requests containing '../' in the query parameter or multipart body
      technique_id: T1190
      data_needed:
        - Web access logs (cs-uri-query, cs-method)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies path traversal in multipart filename handling
  mitigation_plan:
    - priority: immediate
      action: Upgrade @adonisjs/bodyparser to 11.0.0-next.6 or later
      owner: IT Operations
      addresses: CVE-2026-21440
      evidence: Source documentation on vulnerability impact and fix
---

CVE-2026-21440 is a path traversal vulnerability in the `@adonisjs/bodyparser` package affecting versions up to 10.1.1 and 11.0.0-next.1 through 11.0.0-next.5. The vulnerability occurs when the `MultipartFile.move()` method is called without an explicit `name` parameter, allowing an attacker-provided `filename` in a `multipart/form-data` request to be concatenated into a destination path using `path.join()`. This enables attackers to escape the intended upload directory and overwrite arbitrary files on the server. The vulnerability has been confirmed fixed in `@adonisjs/bodyparser@10.1.2` and `11.0.0-next.6`.

## Impact

Successful exploitation allows an unauthenticated attacker to write or overwrite arbitrary files on the server filesystem. This can lead to remote code execution (RCE) if an attacker overwrites sensitive configuration files, web roots, or script files executed by the server.

## Recommendation

- Upgrade `@adonisjs/bodyparser` to version 10.1.2 or 11.0.0-next.6 immediately.
- Audit web applications using `@adonisjs/bodyparser` to identify any routes calling `MultipartFile.move()` without an explicit, sanitized `name` option.
- Apply strict filename validation and sanitization for all user-provided file uploads.
