---
title: Unbounded Remote Media Fetch and Video Frame Expansion DoS in mistral.rs
slug: 2026-09-mistral-rs-dos
description: The mistral.rs /v1/chat/completions endpoint suffers from unbounded resource consumption vulnerabilities, allowing unauthenticated remote attackers to trigger OOM kills, disk exhaustion, or CPU saturation.
date: "2026-09-11T00:54:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - resource-exhaustion
vendors:
  - EricLBuehler
products:
  - mistral.rs
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can exhaust server memory, disk space, and CPU by pointing the endpoint at an infinite-streaming HTTP server or a long high-framerate video, causing a complete denial of service.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the mistral.rs chat completion endpoint using host-based firewalls.
      owner: IT Operations
      due: 24h
      evidence: Endpoint is open by default and lacks authentication.
  hunt_leads:
    - lead: Search for OOM killer (exit 137) logs specifically associated with the mistral.rs binary.
      technique_id: T1499
      data_needed:
        - Syslog/dmesg entries
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Dynamic reproduction confirmed OOM kill (exit 137) after memory exhaustion.
---

The mistral.rs OpenAI-compatible HTTP server contains multiple critical vulnerabilities in its media handling logic that lead to denial of service (DoS). Specifically, the `/v1/chat/completions` endpoint allows unauthenticated users to provide arbitrary remote URLs for images, audio, or video. The server-side code uses `reqwest::get().bytes().await?.to_vec()` to fetch these resources without enforcing any byte limits, content-length validation, or fetch timeouts. An attacker can supply a URL pointing to an infinite HTTP stream or a malicious payload, causing the server process to buffer data until it exhausts all available system memory, leading to an OOM kill. Furthermore, the video processing component utilizes FFmpeg to extract frames. When the `num_frames` parameter is set to `None` (which occurs by default in the chat completion logic), FFmpeg extracts every frame of a video to the local disk. By providing a high-framerate, long-duration video, an attacker can rapidly consume all available disk space and saturate CPU resources.

## Attack Chain

1. Attacker identifies a target server running an unauthenticated mistral.rs instance.
2. Attacker prepares an HTTP server controlled by them to host malicious media content.
3. Attacker constructs a JSON payload for the `/v1/chat/completions` endpoint containing a remote URL pointing to their malicious host.
4. The mistral.rs server receives the request and initializes an asynchronous fetch of the attacker-supplied URL.
5. The server buffer logic consumes incoming bytes indefinitely due to the absence of byte limits.
6. Memory utilization of the mistral.rs process spikes continuously until the Linux kernel invokes the OOM killer (exit code 137).
7. In the video scenario, the server invokes FFmpeg, which begins writing thousands of extracted PNG frames to `/tmp/mistralrs_video/`.
8. Final objective is achieved: the server process is killed or the disk partition is fully saturated, rendering the service unavailable.

## Impact

The vulnerability affects any deployment of mistral.rs that exposes the `/v1/chat/completions` endpoint to the network. Because the endpoint lacks authentication by default, the barrier to exploitation is minimal. Successful exploitation results in complete service unavailability, necessitating a manual restart of the server process. Impact includes forced downtime for AI-powered services relying on this backend, potential disk write amplification, and resource exhaustion of the host environment.

## Recommendation

Prioritize restricting network access to the mistral.rs management and chat completion ports if they are exposed to untrusted environments. Implement a Web Application Firewall (WAF) or proxy layer to validate and filter incoming JSON request schemas, specifically monitoring for `image_url` and `video_url` parameters. Audit the server environment for the existence of large files in `/tmp/mistralrs_video/` which may indicate exploitation attempts. Detection engineering teams should implement monitoring for unexpected OOM killer events (exit code 137) associated with the mistral.rs process.
