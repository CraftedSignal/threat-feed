---
title: DICOM Heap Overflow in Orthanc Server
slug: 2026-05-dicom-heap-overflow
description: A heap overflow vulnerability exists within the DICOM file format, potentially allowing an attacker to target an Orthanc server during image uploads, leading to an out-of-bounds write.
date: "2026-05-28T10:02:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dicom
  - heap overflow
  - orthanc
  - medical imaging
products:
  - Orthanc
  - Pydicom
  - GDCM
references:
  - https://blog.talosintelligence.com/dicom-pydicom-gdcm-and-orthanc-a-technical-tour-of-what-really-happens-in-the-heap/
rules:
  - title: Detect Suspiciously Large DICOM File Uploads to Orthanc
    description: Detects suspicious HTTP POST requests to Orthanc server with unusually large DICOM files, potentially indicating an attempt to exploit a heap overflow.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect DICOM Uploads from Unusual Source IPs
    description: Detects DICOM uploads to Orthanc server originating from unusual or unexpected source IP addresses, which might indicate unauthorized access or malicious activity.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A heap overflow vulnerability has been discovered in the handling of DICOM files, potentially affecting systems that automatically ingest and process these files. This vulnerability can be exploited by crafting malicious DICOM files that trigger an out-of-bounds write when parsed. The research highlights the risks associated with automated DICOM processing, particularly in Picture Archiving and Communication Systems (PACS) used in hospitals. The focus of the research is to demonstrate how an Orthanc server can be targeted during image upload, leading to a heap overflow.

## Attack Chain

1. An attacker crafts a malicious DICOM file designed to exploit the heap overflow vulnerability.
2. The attacker uploads the crafted DICOM file to an Orthanc server via HTTP.
3. The Orthanc server receives the DICOM file and initiates the parsing process.
4. During parsing, the vulnerable DICOM decoder within Orthanc attempts to allocate memory based on malformed data in the DICOM file.
5. Due to incorrect size calculations, the decoder allocates an insufficient buffer on the heap.
6. When the decoder attempts to write data into the undersized buffer, it overflows into adjacent memory regions on the heap.
7. This out-of-bounds write corrupts critical data structures, potentially leading to arbitrary code execution.
8. The attacker gains control of the Orthanc server.

## Impact

A successful heap overflow exploit could allow an attacker to execute arbitrary code on the Orthanc server. This could lead to unauthorized access to sensitive medical images and patient data stored within the PACS system. Compromise of a PACS server could disrupt hospital operations, violate patient privacy, and potentially impact patient care. While the number of affected installations is unknown, the widespread use of DICOM and Orthanc in healthcare makes this a potentially significant threat.

## Recommendation

*   Deploy the Sigma rule provided below to detect suspicious DICOM file uploads based on file size and source IP to your SIEM and tune for your environment.
*   Monitor Orthanc server logs for errors related to DICOM parsing and memory allocation.
*   Implement strict input validation and sanitization for all DICOM files processed by Orthanc servers.
