---
brief_id: brief-2026-11-09-gstreamer-uri-traversal
event_id: brief-2026-11-09-gstreamer-uri-traversal
revision: 2
activity_at: "2026-11-09T16:07:25Z"
revision_history:
  - revision: 2
    at: "2026-11-09T16:07:25Z"
    checksum: sha256:e2fba7d992fc16e28e23ee4324afc93f40f67ddadf9e988d648c6486454b2e94
    summary: added coverage for GStreamer
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - priority_signals
      - references
      - tags
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4408
title: 'GStreamer: Arbitrary local file read via adaptive streaming demuxers (CVE-2026-121629)'
slug: 2026-11-gstreamer-uri-traversal
description: A vulnerability in GStreamer adaptive streaming demuxers allows attackers to read arbitrary local files by injecting file:// URIs into media manifests.
date: "2026-11-09T13:48:19Z"
lastmod: "2026-11-09T16:05:46Z"
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
  validation_status: Needs environment validation for internal GStreamer usage.
cpes:
  - cpe:2.3:a:gstreamer:gstreamer:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
vendors:
  - GStreamer
products:
  - GStreamer (adaptive streaming demuxers)
  - GStreamer
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: An attacker who controls a manifest URL, or who can inject content into an HTTP manifest response, can include file:// URIs pointing to arbitrary local files, causing the affected application to read and process those files.
    confidence_band: high
cves:
  - id: CVE-2026-121629
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121629
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4408
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory applications using GStreamer libraries for HLS, DASH, or MSS streaming.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects GStreamer adaptive streaming demuxers.
    - action: Perform an inventory of all installed software to identify dependencies on GStreamer libraries
      owner: IT Operations
      due: 48h
      evidence: Source advises of vulnerabilities requiring mitigation once patches are available
  hunt_leads:
    - lead: Identify applications performing unexpected file I/O operations from within network-facing media processing components.
      technique_id: T1592
      data_needed:
        - Process file system activity logs (e.g., procmon, auditd) filtered by processes using GStreamer libraries.
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can use file:// URIs to force the application to read arbitrary local files.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor patches for CVE-2026-121629 when available.
      owner: IT Operations
      addresses: CVE-2026-121629
      evidence: Official fix pending vendor release.
    - priority: immediate
      action: Apply security updates as soon as GStreamer project releases patches for these identified vulnerabilities
      owner: IT Operations
      addresses: Multiple GStreamer vulnerabilities
      evidence: Source notes existence of multiple vulnerabilities without patch availability yet
updates:
  - at: "2026-11-09T16:05:46Z"
    level: L1
    summary: added coverage for GStreamer
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4408
---

A vulnerability exists in GStreamer's adaptive streaming demuxers (HLS, DASH, and MSS) where URI schemes for remote resources are not validated during the processing of media manifests. An attacker who can influence the manifest URL or inject content into the manifest response can force the GStreamer-based application to process file:// URIs. This results in the application reading local files from the filesystem. In server-side environments such as media proxies, recorders, or downloaders, this can lead to the disclosure of sensitive files or the enumeration of file existence via error responses.

## Impact

Successful exploitation allows unauthorized disclosure of arbitrary local files accessible to the application process. Attackers may also infer the existence of files on the system based on differential error responses returned by the application.

## Recommendation

* Inventory all applications and services utilizing GStreamer for adaptive media streaming (HLS, DASH, MSS) to identify potential exposure.
* Implement strict input validation or sanitization for all media manifest URIs to ensure only expected schemes (e.g., http, https) are processed.
* Monitor for applications attempting to access unauthorized local file paths via network-oriented media processing components.
* Patch or update GStreamer libraries as soon as an official security update is released by the GStreamer maintainers for CVE-2026-121629.
