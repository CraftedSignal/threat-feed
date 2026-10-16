---
title: Integer Overflow in JavaCV IPCameraFrameGrabber Leads to Denial of Service
slug: 2026-10-javacv-dos
description: An integer overflow vulnerability (CVE-2026-102834) in JavaCV's IPCameraFrameGrabber allows a network attacker to cause a permanent CPU-spinning denial-of-service by sending a crafted HTTP Content-Length header.
date: "2026-10-16T22:29:00Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:bytedeco:javacv:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - java
vendors:
  - Bytedeco
products:
  - JavaCV (< 1.5.14)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This results in a permanent 100% CPU usage hang of the calling thread, which cannot be interrupted by the application, leading to a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-102834
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-rxjv-24xq-76wc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102834
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  mitigation_plan:
    - priority: immediate
      action: Upgrade JavaCV to version 1.5.14 or later
      owner: Development
      addresses: CVE-2026-102834
      evidence: JavaCV versions < 1.5.14 are vulnerable.
---

The JavaCV library contains a critical vulnerability in the `IPCameraFrameGrabber` class (CVE-2026-102834) that stems from the lack of bounds checking on the `Content-Length` header parsed from multipart MJPEG HTTP streams. Applications using this class for camera stream ingestion are susceptible to a denial-of-service attack. A remote attacker - either a compromised camera device or a network-position attacker capable of tampering with unencrypted HTTP traffic - can send a crafted `Content-Length` header with a value between 1,073,741,825 and 2,147,483,647.

When `ensureBufferCapacity(int)` processes this value, the internal buffer-growth routine enters an infinite loop due to signed 32-bit integer overflow, where the capacity variable oscillates between negative values and zero. This causes the thread executing the `grab()` method to consume 100% of a CPU core permanently. The thread becomes non-responsive to interrupts, timeouts, or socket closures, effectively hanging the application thread until the entire JVM process is terminated. This affects all JavaCV versions prior to 1.5.14.

## Attack Chain

1. Attacker monitors or compromises the network path between a camera and the target application.
2. The target application initiates a connection to an MJPEG stream using `IPCameraFrameGrabber`.
3. The attacker intercepts the HTTP response from the camera stream before it reaches the victim.
4. The attacker injects a malicious HTTP header `Content-Length` with a value in the range [1073741825, 2147483647].
5. The `IPCameraFrameGrabber` parses the malicious header into the `contentLength` variable.
6. The `ensureBufferCapacity` method is called, triggering the unsigned integer multiplication loop.
7. Integer overflow causes the `capacity` variable to wrap to `Integer.MIN_VALUE` and eventually `0`, creating an infinite loop.
8. The CPU utilization of the affected application thread hits 100%, causing a thread-level denial of service.

## Impact

The vulnerability allows an attacker to permanently disable the camera-grabbing functionality of any application using affected versions of JavaCV. In environments where applications spawn individual threads for multiple cameras, an attacker can trigger this vulnerability across multiple connections, leading to resource exhaustion, elevated CPU load, and a complete system-level denial of service.

## Recommendation

Update the `org.bytedeco:javacv` dependency to version 1.5.14 or later across all applications utilizing `IPCameraFrameGrabber`. Teams should also prioritize upgrading camera infrastructure to support HTTPS to mitigate the risk of network-position attackers tampering with the plaintext HTTP response headers.
