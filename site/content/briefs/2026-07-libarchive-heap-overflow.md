---
title: Libarchive Heap Overflow and Out-of-Bounds Read via Pax Extended Header (CVE-2026-15028)
slug: 2026-07-libarchive-heap-overflow
description: A heap overflow and out-of-bounds read vulnerability (CVE-2026-15028) has been identified in the Libarchive library, triggered by parsing a tar archive with a specially crafted pax extended header, potentially leading to denial of service or arbitrary code execution.
date: "2026-07-15T07:42:10Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - vulnerability
  - libarchive
  - heap-overflow
  - oob-read
  - rce
  - dos
  - supply-chain
products:
  - Libarchive
cves:
  - id: CVE-2026-15028
    cvss: 3.9
    epss: 0.00203
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-15028
---

A critical vulnerability, tracked as CVE-2026-15028, has been discovered in the widely used Libarchive library. This flaw manifests as both a heap overflow and an out-of-bounds read error when the library processes a `tar` archive containing a maliciously crafted pax extended header. The vulnerability can be triggered when any application or system component leveraging Libarchive attempts to parse such an archive. Successful exploitation could lead to severe consequences, including denial of service, where the application crashes or becomes unresponsive, or potentially arbitrary code execution, granting attackers control over the vulnerable system. Given Libarchive's pervasive use across various operating systems and applications for archive manipulation, the potential impact is significant, warranting immediate attention from defenders to mitigate risks.

## Attack Chain

1. **Attacker crafts malicious tar archive**: An attacker creates a `.tar` archive file that contains a specially malformed pax extended header designed to trigger the heap overflow and out-of-bounds read vulnerability within Libarchive.
2. **Delivery of malicious archive**: The crafted `.tar` archive is delivered to a target system or application. This could occur through various vectors, such as email attachments, malicious downloads from compromised websites, or integration into a software package.
3. **Victim application processes archive**: A vulnerable application or system component on the victim's side, which incorporates or uses the Libarchive library, attempts to open, extract, or process the received malicious `.tar` archive.
4. **Libarchive parsing triggered**: The Libarchive library begins parsing the `.tar` file, eventually encountering and attempting to interpret the malformed pax extended header embedded within the archive.
5. **Heap overflow / OOB read occurs**: The malformed header causes the Libarchive library to perform an out-of-bounds read or trigger a heap overflow condition during the header parsing process due to incorrect memory handling.
6. **Memory corruption / Information disclosure**: This memory access error can lead to controlled memory corruption, allowing the attacker to overwrite critical data in memory, or result in the leakage of sensitive information from adjacent memory regions.
7. **Denial of Service or Arbitrary Code Execution**: Successful exploitation of the memory corruption can either cause the vulnerable application to crash, leading to a denial of service, or enable the attacker to execute arbitrary code within the security context of the compromised application.

## Impact

The successful exploitation of CVE-2026-15028 can lead to significant impact, primarily denial of service or arbitrary code execution. Denial of service would render the affected application or system components unusable, disrupting critical services. If arbitrary code execution is achieved, attackers could gain full control over the compromised system, allowing for data theft, further system compromise, or installation of additional malware. The widespread use of the Libarchive library means that numerous applications and systems could be susceptible, although specific targeting details or victim counts are not yet available.

## Recommendation

* Patch CVE-2026-15028 immediately on all systems and applications that utilize the Libarchive library to prevent exploitation.
* Monitor systems that process `.tar` archives for unusual process crashes or unexpected memory access patterns, which could indicate attempts to exploit CVE-2026-15028.
* Ensure that all software dependencies, particularly fundamental libraries like Libarchive, are regularly updated to their latest versions as recommended by vendors to address vulnerabilities such as CVE-2026-15028.
