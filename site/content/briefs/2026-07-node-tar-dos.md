---
title: node-tar Denial-of-Service Vulnerability via Negative Tar Entry Size (CVE-2026-59874)
slug: 2026-07-node-tar-dos
description: A denial-of-service vulnerability, identified as CVE-2026-59874, exists in the 'node-tar' library, allowing a negative tar entry size to trigger an infinite loop when an archive is being replaced, potentially leading to system unavailability.
date: "2026-07-12T07:04:31Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:isaacs:tar:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - node-tar
  - cve
products:
  - node-tar
cves:
  - id: CVE-2026-59874
    cvss: 7.5
    epss: 0.00291
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59874
---

The Microsoft Security Response Center (MSRC) has published details for CVE-2026-59874, a high-severity denial-of-service vulnerability affecting the `node-tar` library. This flaw can be triggered when a system attempts to replace an existing archive with a specially crafted tar file containing an entry with a negative size. Processing such a malicious archive leads to an infinite loop within the `node-tar` library, consuming excessive system resources and causing the affected application or service to become unresponsive. This vulnerability poses a risk to any application or service that utilizes `node-tar` for archive handling, potentially leading to critical service disruptions.

## Attack Chain

1. An attacker creates a malicious tar archive.
2. The attacker embeds an entry within this archive that specifies a negative size value.
3. The attacker delivers this crafted tar archive to a target system.
4. A vulnerable application or service on the target system attempts to process the malicious archive using the `node-tar` library.
5. Specifically, the application initiates an archive replacement operation involving the malicious tar file.
6. The `node-tar` library, when parsing the tar entry with the negative size during the replacement, enters an infinite loop.
7. This infinite loop consumes all available CPU and memory resources on the system.
8. The affected application or the entire host system becomes unresponsive, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-59874 leads to a denial-of-service condition for applications utilizing the vulnerable `node-tar` library. This could manifest as severe resource exhaustion (CPU, memory), causing the affected application to hang, crash, or become entirely unresponsive. While no specific victims or targeting sectors are mentioned, any system processing untrusted tar archives with vulnerable versions of `node-tar` could be impacted, leading to significant operational disruptions.

## Recommendation

* Patch affected systems immediately by upgrading the `node-tar` library to a version that addresses CVE-2026-59874. Consult the `node-tar` project for specific remediation guidance.
* Review applications that use the `node-tar` library to identify vulnerable instances.
