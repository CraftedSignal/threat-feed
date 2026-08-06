---
title: Denial of Service Vulnerability in GStreamer gst-plugins-good
slug: 2026-08-gstreamer-dos
description: A heap memory exhaustion vulnerability in the GStreamer gst-plugins-good package allows unauthenticated attackers to crash services via unbounded reassembly buffer growth.
date: "2026-08-06T11:23:04Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - memory-exhaustion
  - gstreamer
vendors:
  - GStreamer
products:
  - gst-plugins-good
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote, unauthenticated attacker can send a continuous stream of RTP fragments without ever transmitting an end-of-fragment marker, causing the reassembly buffer to grow without bound until process memory is exhausted.
    confidence_band: high
cves:
  - id: CVE-2026-18649
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18649
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Patch gst-plugins-good across all affected media processing assets
      owner: IT Operations
      addresses: CVE-2026-18649
      evidence: Source explicitly links the vulnerability to unpatched rtph264depay and rtph265depay elements
---

CVE-2026-18649 describes a critical denial of service vulnerability in the GStreamer gst-plugins-good package. The flaw resides within the rtph264depay and rtph265depay elements, which are responsible for depayloading H.264 and H.265 video streams respectively. These elements fail to implement a maximum size limit on the reassembly buffer when processing fragmented RTP packets. By intentionally sending a continuous stream of RTP fragments that lacks a proper end-of-fragment marker, an unauthenticated remote attacker can force the application to allocate memory continuously. This behavior leads to heap memory exhaustion and the eventual termination of the GStreamer-based process. This vulnerability affects any application or multimedia framework utilizing these specific GStreamer elements for RTP stream handling, potentially causing service outages in streaming infrastructure or media processing pipelines.

## Impact

Successful exploitation results in an immediate denial of service for the target application or service relying on GStreamer for media ingestion. Because the process terminates due to memory exhaustion, any active streams being handled by the process are dropped. Given the widespread use of GStreamer in media servers, embedded devices, and surveillance systems, the impact can range from local service disruption to wide-scale outages of media processing infrastructure.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:
- Upgrade the GStreamer gst-plugins-good package to the latest patched version across all affected environments as identified by the vendor's security advisory.
- Audit network ingress traffic for incoming RTP streams targeting GStreamer-based services to identify unusual traffic volumes or long-duration fragmented RTP sessions.
- Implement monitoring for process-level memory consumption on servers hosting GStreamer pipelines to detect anomalies characteristic of memory exhaustion attacks.
- Consult the GStreamer security bulletin for specific version numbers that include the patch for CVE-2026-18649.
