---
title: Denial of Service Vulnerability in Gumlet php-image-resize
slug: 2026-10-php-image-resize-dos
description: The Gumlet php-image-resize library before 3.0.1 is vulnerable to a denial-of-service condition via memory exhaustion when processing specially crafted image uploads.
date: "2026-10-12T18:33:58Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:gumlet:php-image-resize:*:*:*:*:*:*:*:*
vendors:
  - Gumlet
products:
  - php-image-resize (< 3.0.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Remote attackers can upload small, highly compressed images that decode to large bitmaps, exhausting PHP memory and terminating the worker process.
    confidence_band: high
cves:
  - id: CVE-2026-109398
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109398
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Gumlet php-image-resize to 3.0.1 or later.
      owner: IT Operations
      due: 48h
      evidence: Source states php-image-resize before 3.0.1 is vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Implement image upload size and dimension validation at the web application layer or WAF.
      owner: SOC
      addresses: CVE-2026-109398
      evidence: Vulnerability stems from lack of pixel limits during image processing.
---

The Gumlet php-image-resize library, specifically versions prior to 3.0.1, contains a denial of service (DoS) vulnerability. The flaw exists within the ImageResize constructor located in 'lib/ImageResize.php'. The component fails to enforce pixel count limits when passing images to the PHP GD library's 'imagecreatefrom*' functions. A remote attacker can exploit this by uploading a small, highly compressed image file that, upon decompression by the GD library, expands into an excessively large bitmap in memory. This process rapidly exhausts the PHP memory limit, causing the worker process to crash or terminate. This vulnerability impacts applications relying on this library for server-side image manipulation and is particularly dangerous in environments that allow unauthenticated or user-supplied image uploads.

## Impact

Successful exploitation results in the immediate termination of the PHP worker process handling the request. Repeated exploitation can lead to a complete denial of service for the web application, exhausting server resources and preventing legitimate users from accessing services.

## Recommendation

* Upgrade the 'Gumlet php-image-resize' library to version 3.0.1 or later immediately to include pixel limit enforcement.
* In environments where immediate patching is not possible, implement an upstream WAF rule to validate image dimensions before passing files to the PHP backend.
* Configure PHP memory limits (memory_limit) to prevent a single request from exhausting total system RAM, though this does not mitigate the application-level worker crash.
