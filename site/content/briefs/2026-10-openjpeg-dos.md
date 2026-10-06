---
title: Denial of Service Vulnerability in OpenJPEG
slug: 2026-10-openjpeg-dos
description: A vulnerability in the OpenJPEG library allows a remote, unauthenticated attacker to cause a denial-of-service condition through the processing of maliciously crafted input.
date: "2026-10-06T12:43:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
vendors:
  - OpenJPEG
products:
  - OpenJPEG
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can exploit a vulnerability in OpenJPEG to perform a Denial of Service attack.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3752
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: medium_term
      action: Identify and update all applications utilizing the affected OpenJPEG library
      owner: IT Operations
      addresses: OpenJPEG vulnerability
      evidence: Source reporting identifies a DoS vulnerability in the library.
---

The OpenJPEG library, an open-source JPEG 2000 codec, contains a security vulnerability that can be exploited by a remote, unauthenticated attacker to induce a denial-of-service (DoS) condition. The vulnerability manifests during the parsing or processing phase of input files, where an attacker providing a specially crafted JPEG 2000 image can trigger resource exhaustion or an application crash. As OpenJPEG is widely integrated into various image processing suites, document viewers, and graphics libraries, the impact is highly dependent on how the host application handles library exceptions and resource allocation. Defenders should identify applications within their environments that link against vulnerable versions of OpenJPEG and monitor for abnormal resource consumption or unexpected termination of image-processing services.

## Impact

Successful exploitation results in a denial-of-service, leading to the instability or crash of the host application that relies on the OpenJPEG library. Depending on the architecture, this can impact availability for services that automatically process user-uploaded images or documents, potentially leading to widespread service degradation in environments where affected software is deployed at scale.

## Recommendation

Identify and update all applications utilizing the affected version of the OpenJPEG library. Ensure that image-processing components are isolated with resource limits to mitigate the impact of potential DoS conditions, and monitor application logs for recurring crash events or memory exhaustion patterns associated with image parsing services.
