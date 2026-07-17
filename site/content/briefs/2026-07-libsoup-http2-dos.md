---
title: Libsoup HTTP/2 Frame Window Exhaustion Remote Denial of Service
slug: 2026-07-libsoup-http2-dos
description: A remote denial of service vulnerability, CVE-2026-15713, exists in the soupcache component of the Libsoup library due to a memory leak that leads to HTTP/2 frame window exhaustion, potentially causing application crashes or unresponsiveness.
date: "2026-07-17T07:05:28Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - denial-of-service
  - vulnerability
  - http/2
  - libsoup
  - memory-leak
vendors:
  - GNOME
products:
  - Libsoup
cves:
  - id: CVE-2026-15713
    cvss: 5.9
    epss: 0.00349
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15713
---

A remote denial-of-service vulnerability, identified as CVE-2026-15713, has been discovered in the Libsoup library, specifically within its `soupcache` component. This vulnerability is attributed to a memory leak that occurs during the handling of HTTP/2 frame windows. When exploited, this flaw can lead to the exhaustion of memory resources on affected systems, causing applications or services that rely on the vulnerable Libsoup version to become unresponsive or crash entirely. The vulnerability affects the GNOME Libsoup library, which is a core component used by various Linux applications for HTTP client operations. While the MSRC advisory does not detail specific exploitation in the wild, the nature of the vulnerability implies that a remote attacker could trigger the denial of service by sending a series of specially crafted HTTP/2 requests. This poses a significant risk to the availability and stability of services utilizing the vulnerable library, potentially impacting critical systems.

## Attack Chain

1. **Crafted Request Initiation**: A remote attacker sends specially crafted HTTP/2 requests to a server or application utilizing a vulnerable version of the Libsoup library.
2. **Vulnerability Trigger**: The `soupcache` component within the Libsoup library processes these malformed HTTP/2 requests.
3. **Memory Leak**: Due to a flaw in the management of HTTP/2 frame windows, the processing of the crafted requests causes a memory leak within the application's process.
4. **Resource Exhaustion**: The attacker continues to send these requests, repeatedly triggering the memory leak and consuming increasing amounts of system memory.
5. **Denial of Service**: As system memory resources become exhausted, the application or service running the vulnerable Libsoup library becomes unstable, unresponsive, or crashes, leading to a denial of service for legitimate users.

## Impact

Successful exploitation of CVE-2026-15713 results in a denial of service for applications or services dependent on the vulnerable Libsoup library. This can manifest as application crashes, hangs, or complete unresponsiveness, rendering the service unavailable to users. The impact can range from temporary inconvenience to significant operational disruption, depending on the criticality of the affected application and the frequency of attacks. While specific victim counts or targeted sectors are not provided, any system running the affected Libsoup version could be a target.

## Recommendation

* Patch CVE-2026-15713 by updating the Libsoup library to a remediated version provided by GNOME or your Linux distribution vendor immediately.
* Monitor network connections for unusually high volumes of HTTP/2 requests targeting services using Libsoup, which could indicate a DoS attempt related to CVE-2026-15713.
