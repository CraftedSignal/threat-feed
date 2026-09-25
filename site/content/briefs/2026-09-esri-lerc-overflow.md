---
title: Heap-based Out-of-Bounds Write in Esri LERC
slug: 2026-09-esri-lerc-overflow
description: A heap-based out-of-bounds write vulnerability in Esri LERC versions 4.1.0 and earlier allows remote, unauthenticated attackers to cause a denial of service via crafted imagery.
date: "2026-09-25T22:55:52Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:esri:lerc:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - dos
vendors:
  - Esri
products:
  - LERC (<= 4.1.0)
cves:
  - id: CVE-2026-10758
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10758
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade LERC library to version 4.1.1 or later
      owner: IT Operations
      addresses: CVE-2026-10758
      evidence: NVD vulnerability disclosure
---

The Esri LERC (Limited Error Raster Compression) library, used for rapid encoding and decoding of image data, contains a heap-based out-of-bounds write vulnerability tracked as CVE-2026-10758. The flaw originates from an integer overflow during the processing of image data. An unauthenticated, remote attacker can exploit this by providing a specifically crafted image file to an application that utilizes an affected version of the LERC library (4.1.0 and earlier). Successful exploitation leads to an application crash, resulting in a denial of service. Because LERC is integrated into various geospatial and mapping applications to handle pixel data, this vulnerability impacts any downstream software relying on vulnerable versions for image decoding.

## Impact

The vulnerability poses a denial-of-service risk to applications integrating the LERC library. In environments where these applications are mission-critical for geospatial analysis or infrastructure monitoring, an exploitation event can lead to significant service degradation and operational downtime.

## Recommendation

* Identify all internal and vendor-supplied applications that include the LERC library as a dependency.
* Upgrade instances of the LERC library to version 4.1.1 or later to remediate CVE-2026-10758.
* Monitor application logs for abnormal crashes or process terminations associated with the ingestion of external image or raster data.
