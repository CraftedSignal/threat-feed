---
brief_id: brief-2026-10-26-zip-rust-dos-f3aab68b
event_id: brief-2026-10-26-zip-rust-dos-f3aab68b
revision: 1
activity_at: "2026-10-26T17:45:50Z"
title: 'zip Rust Library: Denial of Service via ZIP64 Uncompressed Size (CVE-2026-115909)'
slug: 2026-10-zip-rust-dos-f3aab68b
description: The zip Rust library is vulnerable to a denial-of-service condition where a malicious ZIP64 archive triggers an unrecoverable process abort through an impossible memory allocation request.
date: "2026-10-26T17:45:50Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:zip_project:zip:*:*:*:*:*:rust:*:*
products:
  - zip (< 9.0.0)
cves:
  - id: CVE-2026-115909
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115909
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Software Engineering
  immediate_actions:
    - action: Update zip crate dependency to 9.0.0 or later across all software repositories
      owner: Software Engineering
      due: 48h
      evidence: This issue is fixed in version 9.0.0.
  hunt_leads:
    - lead: Identify applications repeatedly crashing during file extraction
      data_needed:
        - Application error logs
        - OS process termination logs (e.g., SIGABRT signals)
        - Crash dumps or stack traces referencing the zip library
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A small archive can request an impossible capacity, causing the infallible allocation path to abort the process.
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected projects to zip version 9.0.0
      owner: Software Engineering
      addresses: CVE-2026-115909
      evidence: This issue is fixed in version 9.0.0.
---

The zip Rust library (versions 1.3.0 through 8.x) contains a vulnerability in `ZipArchive::extract` where the library trusts an attacker-controlled uncompressed size value from a ZIP64 archive. The library uses this value to initialize memory via `Vec::with_capacity`. If a malicious archive specifies an excessively large size, the application attempts an impossible memory allocation. Because this allocation path is infallible in Rust, the process is aborted immediately. This abort cannot be caught by `catch_unwind` or worker threads, enabling a persistent denial-of-service attack against any application that processes untrusted ZIP archives using this library.

## Impact

The vulnerability results in a total denial-of-service for any process using the affected zip library to extract ZIP64 archives. The crash is non-recoverable, and the process is immediately terminated by the operating system, impacting the availability of the host application.

## Recommendation

* Update the zip dependency to version 9.0.0 or later in all projects.
* Identify and audit applications that utilize the zip crate to process externally supplied or untrusted ZIP files.
* Implement strict input validation on the size of incoming ZIP archives before passing them to the `ZipArchive::extract` function.
