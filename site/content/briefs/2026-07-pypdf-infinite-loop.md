---
title: 'pypdf: Possible infinite loop for not terminated inline images'
slug: 2026-07-pypdf-infinite-loop
description: An attacker can exploit a vulnerability in the pypdf library by crafting a PDF containing a malformed, not terminated inline image. When this malicious PDF is processed by pypdf, such as during text extraction, it triggers an infinite loop, leading to a denial of service. The issue is resolved in pypdf version 6.14.1.
date: "2026-07-23T16:39:59Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:pypdf_project:pypdf:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - python
  - library
vendors:
  - pypdf
products:
  - pypdf (< 6.14.1)
cves:
  - id: CVE-2026-59936
    cvss: 7.5
    epss: 0.00345
references:
  - https://github.com/advisories/GHSA-5xf7-4p34-54qr
  - https://github.com/py-pdf/pypdf/releases/tag/6.14.1
  - https://github.com/py-pdf/pypdf/pull/3891
---

A high-severity denial of service (DoS) vulnerability, tracked as CVE-2026-59936, has been identified in the widely used Python library `pypdf`. This vulnerability affects all `pypdf` versions prior to 6.14.1. An attacker can exploit this flaw by crafting a specially malformed PDF document that contains a non-terminated inline image. When a vulnerable application or system attempts to parse the content stream of such a PDF, for example, during text extraction, the `pypdf` library enters an uncontrolled infinite loop. This endless processing consumes excessive system resources, leading to the application becoming unresponsive and effectively causing a denial of service. The vulnerability was publicly disclosed on 2026-07-23 and a fix was released in `pypdf` version 6.14.1. Organizations using `pypdf` to process untrusted PDF inputs are at risk.

## Attack Chain

1. An attacker crafts a malicious PDF document designed to exploit the `pypdf` library.
2. The crafted PDF incorporates a malformed, non-terminated inline image within one of its page content streams.
3. A target application or system processes this malicious PDF using a vulnerable version of the `pypdf` library (e.g., any version prior to 6.14.1).
4. During a PDF operation such as text extraction, `pypdf` attempts to parse the content stream containing the malformed inline image.
5. Upon encountering the improperly terminated inline image, the `pypdf` parsing logic enters an infinite loop, continuously attempting to process the malformed data.
6. This infinite loop leads to unchecked resource consumption (e.g., 100% CPU utilization), causing the application or system to hang or crash, resulting in a denial of service.

## Impact

The successful exploitation of CVE-2026-59936 results in a denial of service (DoS) condition. Any application or service that relies on the `pypdf` library to process potentially untrusted PDF documents is at risk. If an attacker delivers a malicious PDF, the affected application will experience severe resource exhaustion, primarily high CPU usage, and will become unresponsive or crash. This can lead to significant operational disruptions, unavailability of critical services, and potential data loss if processes are abruptly terminated. Organizations handling user-submitted PDFs, such as document processing platforms, web forms, or content management systems, are particularly vulnerable to this type of attack.

## Recommendation

* Immediately upgrade the `pypdf` library to version `6.14.1` or newer to remediate `CVE-2026-59936`.
* If upgrading to `pypdf` version `6.14.1` is not immediately feasible, apply the specific code changes detailed in PR `#3891` as a temporary workaround for `CVE-2026-59936`.
* Monitor systems that process PDF documents using `pypdf` for unusual spikes in CPU utilization or application unresponsiveness, which could indicate a denial of service attempt related to this vulnerability.
