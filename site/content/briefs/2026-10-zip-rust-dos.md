---
brief_id: brief-2026-10-26-zip-rust-dos
event_id: brief-2026-10-26-zip-rust-dos
revision: 1
activity_at: "2026-10-26T17:45:37Z"
title: 'zip-rs: Denial of service via unchecked ZIP64 allocation (CVE-2026-115907)'
slug: 2026-10-zip-rust-dos
description: The Rust zip library is vulnerable to a denial-of-service condition where attacker-controlled ZIP64 uncompressed size headers trigger memory allocation panics during extraction, causing service termination.
date: "2026-10-26T17:45:37Z"
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
qa_status:
  verdict: pass
  validation_status: Requires application-level review
cpes:
  - cpe:2.3:a:zip-rs:zip:*:*:*:*:*:rust:*:*
vendors:
  - zip-rs
products:
  - zip (< 9.0.0)
cves:
  - id: CVE-2026-115907
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115907
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  hunt_leads:
    - lead: Identify services that utilize the zip crate and specifically the legacy-zip feature
      data_needed:
        - Application dependency manifests (Cargo.toml files)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: From 5.1.0 until 9.0.0, applications built with the legacy-zip feature can reserve output capacity
  mitigation_plan:
    - priority: immediate
      action: Upgrade the zip crate in all projects to version 9.0.0 or later
      owner: IT Operations
      addresses: CVE-2026-115907
      evidence: This issue is fixed in version 9.0.0.
---

The zip-rs library, specifically when the 'legacy-zip' feature is enabled, contains a vulnerability that allows an attacker to trigger an unhandled panic by supplying a maliciously crafted ZIP archive. The library preallocates output memory based on the ZIP64 uncompressed size field before validating the integrity of the compressed data. This vulnerability affects the Shrink, Reduce, and Implode decoders within the library. If an archive-processing service attempts to extract such a file, the resulting capacity overflow leads to a panic and subsequent termination of the service. This issue is resolved in version 9.0.0.

## Impact
Successful exploitation results in a denial-of-service condition for the application or service consuming the library, as the unhandled panic terminates the processing thread or the entire service process.

## Recommendation
- Update the zip-rs crate to version 9.0.0 or later to ensure the library properly validates compressed stream data before allocating output capacity.
- Audit applications using the 'legacy-zip' feature to determine if they are exposed to untrusted user-supplied ZIP files.
- Implement memory limits or resource constraints on containerized or service-level environments that process uploaded archives to mitigate the impact of unexpected allocation attempts.
