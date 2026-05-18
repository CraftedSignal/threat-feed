---
title: TinyIce Unauthenticated WebRTC Stream Injection Vulnerability
slug: 2026-05-tinyice-webrtc-injection
description: TinyIce versions 0.8.95 through 2.4.1 are vulnerable to unauthenticated stream injection due to a missing authentication check on the WebRTC ingest endpoint (/webrtc/source-offer), allowing a network attacker to hijack broadcasts by publishing arbitrary audio/video to a target mount, replacing the legitimate source's content; patched in version 2.5.0 (CVE-2026-45327).
date: "2026-05-18T17:21:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webrtc
  - stream-injection
  - missing-authentication
vendors:
  - DatanoiseTV
products:
  - tinyice
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Web Servers
references:
  - https://github.com/advisories/GHSA-p7c4-8x34-8j8f
  - https://cwe.mitre.org/data/definitions/306.html
  - https://github.com/DatanoiseTV/tinyice/commit/8067d6b
rules:
  - title: Detect TinyIce WebRTC Unauthenticated SDP Offer
    description: Detects attempted exploitation of the TinyIce unauthenticated WebRTC stream injection vulnerability (CVE-2026-45327) by identifying POST requests to the /webrtc/source-offer endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect TinyIce Authentication Failure for WebRTC Source
    description: Detects TinyIce authentication failures for WebRTC source connections based on log messages after the patch is applied (CVE-2026-45327).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - webserver
rules_count: 2
---

TinyIce, a lightweight streaming server, contains a vulnerability that allows unauthenticated users to inject streams into existing mounts. The vulnerability, present in versions 0.8.95 through 2.4.1, stems from a missing authentication check on the `/webrtc/source-offer` endpoint. Introduced on 2026-02-21, this flaw enables attackers to bypass the intended source password protection and inject arbitrary audio/video content into live broadcasts. This poses a significant threat to the integrity of broadcasts, as attackers can replace legitimate content with malicious or disruptive material. Patched in version 2.5.0, this vulnerability (CVE-2026-45327) requires immediate attention from TinyIce users to prevent potential broadcast hijacking.

## Attack Chain

1.  The attacker identifies a target mount point on a TinyIce server. Mount names are often public, appearing in directory listings, player URLs, and YP listings.
2.  The attacker crafts a malicious SDP (Session Description Protocol) offer for a WebRTC connection.
3.  The attacker sends an HTTP POST request to the `/webrtc/source-offer` endpoint, including the target mount point as a query parameter (`?mount=<mount>`) and the malicious SDP offer in the request body.
4.  The vulnerable TinyIce server, lacking authentication, processes the malicious SDP offer via `WebRTCManager.HandleSourceOffer`.
5.  The server establishes a WebRTC peer connection with the attacker.
6.  The attacker publishes arbitrary audio (Opus) and video (H.264) tracks via the established WebRTC connection.
7.  The TinyIce server broadcasts the attacker's injected audio/video content to all listeners subscribed to the target mount point.
8.  Listeners receive the attacker's injected stream instead of the legitimate source's content, resulting in a broadcast hijack.

## Impact

Successful exploitation allows an attacker to inject arbitrary audio and video content into live broadcasts, effectively hijacking the stream. This can be used to broadcast silence, disruptive noise, malicious content, or competitor branding. While the legitimate publisher can attempt to re-establish their session, the attacker can immediately reconnect, leading to a sustained broadcast hijack until manual intervention occurs. The CVSS 3.1 base score is 7.4 (High), emphasizing the potential for significant integrity impact.

## Recommendation

*   Upgrade TinyIce to version 2.5.0 or later to apply the patch that fixes CVE-2026-45327.
*   Implement the workaround by blocking `POST /webrtc/source-offer` at the reverse proxy to prevent unauthorized access to the vulnerable endpoint.
*   Deploy the Sigma rule "Detect TinyIce WebRTC Unauthenticated SDP Offer" to identify potential exploitation attempts in webserver logs.
*   Deploy the Sigma rule "Detect TinyIce Authentication Failure for WebRTC Source" to monitor for failed authentication attempts after patching or applying workarounds.
