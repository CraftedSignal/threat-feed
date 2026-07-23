---
title: HAProxy Denial of Service Vulnerability (CVE-2026-26080)
slug: 2026-07-haproxy-dos
description: A denial of service vulnerability (CVE-2026-26080) in HAProxy Community Edition versions 3.2.x through 3.3.x before 3.3.3, HAProxy Enterprise, and ALOHA can lead to a loop or crash due to mishandled varint, impacting service availability.
date: "2026-07-23T07:32:02Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - haproxy
vendors:
  - HAProxy
products:
  - HAProxy Community Edition
  - HAProxy Enterprise
  - ALOHA
cves:
  - id: CVE-2026-26080
    cvss: 3.7
    epss: 0.00416
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26080
---

A denial of service (DoS) vulnerability, identified as CVE-2026-26080, has been disclosed affecting HAProxy Community Edition versions 3.2.x up to, but not including, 3.3.3, as well as HAProxy Enterprise and ALOHA products. This flaw stems from improper handling of varint, a method of serializing integers, which can cause the HAProxy instance to enter an infinite loop or crash unexpectedly. Such an event would severely disrupt the availability and performance of applications and services relying on HAProxy for load balancing and proxying. While the full technical details of exploitation are not provided, successful exploitation would lead to service outages and potential data path disruption for affected organizations. The vulnerability specifically targets the core functionality of HAProxy, making it a critical concern for environments deploying these versions.

## Impact

The primary impact of CVE-2026-26080 is a denial of service for any applications or services utilizing vulnerable versions of HAProxy. If exploited, the HAProxy instance could crash or become unresponsive, leading to service outages, degraded performance, and unavailability of critical network resources. Organizations relying on HAProxy for high availability and load balancing could experience significant operational disruption, reputational damage, and potential financial losses due to prolonged downtime. The vulnerability affects a broad range of HAProxy deployments, including enterprise and appliance-based solutions.

## Recommendation

* Patch CVE-2026-26080 by upgrading HAProxy Community Edition to version 3.3.3 or newer immediately on all affected servers. Consult HAProxy Enterprise and ALOHA documentation for specific patch instructions.
* Review HAProxy configurations for unusual traffic patterns that might indicate attempts to trigger the varint mishandling vulnerability.
