---
title: Denial of Service in GStreamer RTSP Support Library via Malformed Digest Headers
slug: 2026-09-gstreamer-rtsp-dos
description: A NULL pointer dereference vulnerability in the GStreamer RTSP support library allows remote, unauthenticated attackers to trigger a denial of service by sending a malformed RTSP request containing specifically crafted whitespace in Digest authentication headers.
date: "2026-09-03T13:21:49Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:gstreamer:gstreamer:*:*:*:*:*:*:*:*
vendors:
  - GStreamer
products:
  - GStreamer RTSP support library
cves:
  - id: CVE-2026-85150
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85150
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Identify GStreamer-dependent services and apply security updates when provided by the vendor
      owner: IT Operations
      addresses: CVE-2026-85150
      evidence: Source states that a NULL pointer dereference flaw exists in GStreamer RTSP support library
---

A NULL pointer dereference vulnerability (CVE-2026-85150) exists in the GStreamer RTSP support library. The issue arises during the parsing of 'Authorization' or 'WWW-Authenticate' headers when using Digest authentication. Attackers can manipulate the placement of whitespace around a parameter's terminator, which causes an integer underflow during internal length calculations. This underflow leads to a memory access violation and a subsequent crash of the process parsing the malformed header. The vulnerability is triggered by a single malformed RTSP request. In a server-side scenario, this allows remote, unauthenticated attackers to cause a denial of service. The same flaw can be exploited against an RTSP client if it connects to a malicious or compromised RTSP server.

## Impact

Successful exploitation results in a denial of service due to the application crashing. No impact on confidentiality or integrity has been confirmed. The vulnerability affects any application or system leveraging the GStreamer RTSP support library for handling RTSP streams, particularly those configured to use Digest authentication.

## Recommendation

1. Inventory all services and applications utilizing the GStreamer library for RTSP handling.
2. Monitor for RTSP traffic patterns containing abnormal whitespace in Digest authentication headers.
3. Apply available patches from the GStreamer project as soon as they are integrated into downstream software distributions.
4. Implement strict request validation at the network perimeter or application gateway for RTSP traffic if immediate patching is not possible.
