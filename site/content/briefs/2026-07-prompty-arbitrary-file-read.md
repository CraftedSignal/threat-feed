---
title: Prompty Arbitrary File Read Vulnerability via File Reference Expansion (CVE-2026-53598)
slug: 2026-07-prompty-arbitrary-file-read
description: A path traversal vulnerability, CVE-2026-53598, in Prompty loaders allows an attacker-controlled `.prompty` file to read arbitrary files accessible to the host application process due to improper validation of `${file:...}` references in frontmatter, leading to sensitive local file disclosure.
date: "2026-07-17T19:47:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-read
  - path-traversal
  - code-execution
  - prompty
vendors:
  - Prompty
products:
  - prompty (PyPI) <= 2.0.0b1
  - '@prompty/core (npm) <= 2.0.0-beta.1'
  - prompty (crates.io) <= 2.0.0-beta.1
  - Prompty.Core (NuGet) <= 2.0.0-beta.1
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An attacker-controlled prompt file could use path traversal or an absolute path to cause the host application to read files accessible to the process.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: An attacker-controlled prompt file could use path traversal or an absolute path to cause the host application to read files accessible to the process.
    confidence_band: high
cves:
  - id: CVE-2026-53598
    cvss: 7.5
    epss: 0.01057
references:
  - https://github.com/advisories/GHSA-wxhm-2mq7-7697
---

CVE-2026-53598 describes an arbitrary file read vulnerability affecting Prompty libraries across multiple ecosystems, including PyPI `prompty` (versions `<= 2.0.0b1`), npm `@prompty/core` (versions `<= 2.0.0-beta.1`), crates.io `prompty` (versions `<= 2.0.0-beta.1`), and NuGet `Prompty.Core` (versions `<= 2.0.0-beta.1`). This flaw stems from improper validation of `${file:...}` references within `.prompty` frontmatter, allowing path traversal (`../`) or absolute paths to read files outside the intended directory. Threat actors could exploit this by providing a specially crafted `.prompty` file to a vulnerable application, leading to the disclosure of sensitive local files accessible to the application's process. The vulnerability was patched in versions `2.0.0b2` and `2.0.0-beta.2`, which enforce stricter path restrictions and canonicalization.

## Attack Chain

1. An attacker crafts a malicious `.prompty` file containing a `${file:...}` reference with a path traversal sequence (e.g., `${file:../etc/passwd}`) or an absolute path (e.g., `${file:/etc/shadow}`) in its frontmatter.
2. The attacker delivers this malicious `.prompty` file to a vulnerable application or convinces a victim to load it, targeting applications using PyPI `prompty` (<= 2.0.0b1), npm `@prompty/core` (<= 2.0.0-beta.1), crates.io `prompty` (<= 2.0.0-beta.1), or NuGet `Prompty.Core` (<= 2.0.0-beta.1).
3. The vulnerable application loads the untrusted `.prompty` file, which includes the frontmatter containing the crafted file reference.
4. The Prompty loader attempts to expand the `${file:...}` reference during processing without properly validating the resolved path against authorized directories or canonicalizing it.
5. The Prompty library's internal logic resolves the path traversal or absolute path, causing the application to read the arbitrary file from the host system.
6. The content of the sensitive file (e.g., `/etc/passwd`, `/etc/shadow`, configuration files) is then processed by the application.
7. The application may log the content, include it in a response, or otherwise expose it, allowing the attacker to receive or extract the contents of the arbitrary file.
8. The attacker achieves sensitive information disclosure, obtaining unauthorized access to local system files.

## Impact

Applications that process untrusted `.prompty` files are at severe risk of arbitrary file disclosure due to CVE-2026-53598. Successful exploitation could lead to attackers reading any file accessible to the vulnerable application's process, including critical configuration files, user credentials, application source code, or sensitive private data. While no specific victim counts are provided, any organization utilizing affected Prompty versions in environments that parse external or user-provided prompt files is vulnerable to significant information theft. The potential damage includes intellectual property loss, system compromise through leaked credentials, and privacy breaches if personal data is exposed.

## Recommendation

* Upgrade all PyPI `prompty` installations to version `2.0.0b2` or higher immediately to remediate CVE-2026-53598.
* Upgrade all npm `@prompty/core` installations to `2.0.0-beta.2` or higher immediately to remediate CVE-2026-53598.
* Upgrade all crates.io `prompty` installations to `2.0.0-beta.2` or higher immediately to remediate CVE-2026-53598.
* Upgrade all NuGet `Prompty.Core` installations to `2.0.0-beta.2` or higher immediately to remediate CVE-2026-53598.
* Review application logs for CVE-2026-53598 exploitation attempts, specifically looking for `prompty` library operations attempting to access files outside expected asset directories.
