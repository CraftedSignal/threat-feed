---
title: Heap Out-of-Bounds Write Vulnerability in Orthanc DICOM Server
slug: 2026-09-orthanc-dicom-dos
description: An integer overflow vulnerability (CVE-2026-87020) in Orthanc DICOM Server versions prior to 1.13.0 allows an authenticated remote attacker to cause a denial-of-service via a crafted PNG or JPEG image.
date: "2026-09-10T16:06:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - ics-medical
  - dos
vendors:
  - Orthanc
products:
  - Orthanc DICOM Server (<1.13.0)
references:
  - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-02
  - https://www.cve.org/CVERecord?id=CVE-2026-87020
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Orthanc DICOM Server to version 1.13.0
      owner: IT Operations
      due: 48h
      evidence: Orthanc recommends users update to v1.13.0
  mitigation_plan:
    - priority: immediate
      action: Isolate Orthanc server from internet and untrusted networks
      owner: Network Security
      addresses: CVE-2026-87020
      evidence: Minimize network exposure for all control system devices
---

Orthanc DICOM Server versions prior to 1.13.0 are susceptible to a heap out-of-bounds write vulnerability, tracked as CVE-2026-87020. The vulnerability stems from an integer overflow in the pitch and buffer-size computation logic when the server decodes PNG or JPEG images. An authenticated remote attacker can exploit this flaw by submitting a specially crafted image file to the DICOM server. Successful exploitation results in memory corruption, leading to a process crash and a denial-of-service (DoS) condition. This vulnerability poses a significant risk to healthcare environments where Orthanc is deployed to manage sensitive medical imaging data, as the crash disrupts the availability of critical imaging services. Organizations are advised to update to version 1.13.0 to remediate this flaw.

## Impact

The vulnerability affects the Healthcare and Public Health sector globally. A successful attack results in the termination of the Orthanc service, preventing clinicians and medical systems from accessing or processing DICOM imagery. Given the dependency of modern radiology workflows on PACS and image management servers like Orthanc, this disruption can directly impact patient care and diagnostic throughput.

## Recommendation

- Upgrade all instances of Orthanc DICOM Server to version 1.13.0 or later immediately to patch CVE-2026-87020.
- Minimize network exposure by isolating DICOM servers from the public internet and ensuring access is restricted to authorized internal networks only.
- Implement network segmentation to place medical imaging infrastructure behind firewalls, restricting direct communication between the DICOM server and non-essential business segments.
- Enforce strict authentication controls for the Orthanc web API to reduce the likelihood of unauthenticated or unauthorized users submitting malicious payloads.
- Monitor Orthanc application logs for recurring service restarts or unexpected process crashes that may indicate exploitation attempts.
