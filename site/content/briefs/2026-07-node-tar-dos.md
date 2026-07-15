---
title: node-tar Denial of Service Vulnerability via NUL Byte
slug: 2026-07-node-tar-dos
description: A Denial of Service (DoS) vulnerability exists in the node-tar library, triggered by an uncaught exception due to a NUL byte within PAX path or linkpath records.
date: "2026-07-15T07:44:16Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - node-tar
products:
  - node-tar
cves:
  - id: CVE-2026-59875
    cvss: 5.3
    epss: 0.00291
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59875
---

The CVE-2026-59875 vulnerability affects the `node-tar` library, a popular Node.js module used for handling tar archives. This Denial of Service (DoS) flaw stems from an uncaught exception that occurs when the library attempts to process a `.tar` archive containing a NUL byte within its PAX path or linkpath records. Attackers can exploit this by crafting a specially malformed `.tar` file and inducing an application to process it, leading to the affected application's unexpected termination. This can disrupt services, degrade application availability, and impact business operations for organizations relying on `node-tar` for archive handling, particularly in environments processing untrusted input. The vulnerability was disclosed by Microsoft Security Response Center.

## Attack Chain

1. An attacker crafts a malicious `.tar` archive containing a NUL byte embedded within the PAX `path` or `linkpath` records.
2. The attacker delivers this specially crafted `.tar` archive to a target application or system, often via untrusted input channels such as file uploads or email attachments.
3. The victim application, which incorporates the `node-tar` library, attempts to extract or process the malicious `.tar` archive.
4. During the parsing of the archive's metadata, the `node-tar` library encounters the embedded NUL byte in the `path` or `linkpath` record.
5. The presence of the NUL byte causes the `node-tar` library to throw an uncaught exception, indicating an unhandled error condition.
6. Due to the uncaught exception, the application utilizing the `node-tar` library terminates abruptly, resulting in a Denial of Service.
7. The application's crash leads to its unavailability, disrupting services and operations dependent on it.

## Impact

The successful exploitation of CVE-2026-59875 results in a Denial of Service (DoS) condition for applications that utilize the `node-tar` library to process `.tar` archives. This leads to an abrupt termination of the affected application, rendering it unavailable to legitimate users and processes. While the source does not specify observed victims or targeted sectors, any organization using `node-tar` to handle potentially untrusted archive files is at risk. The primary damage is service disruption and potential operational downtime, which can lead to financial losses and reputational damage depending on the criticality of the affected application.

## Recommendation

- Immediately apply patches for CVE-2026-59875 to all applications using the `node-tar` library.
- Implement robust input validation and sanitization for all `.tar` archive uploads or inputs to mitigate processing of malformed files.
- Monitor application logs for unexpected crashes or error messages related to `node-tar` processing, indicating potential exploitation attempts or software misconfigurations.
