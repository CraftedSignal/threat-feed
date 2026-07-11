---
title: Setuptools Unicode Normalization Collision Bypass on macOS
slug: 2026-07-setuptools-unicode-bypass
description: A vulnerability, CVE-2026-59890, affects the setuptools project, allowing a MANIFEST.in exclusion bypass during source distribution package creation due to Unicode normalization collisions (NFC/NFD) on macOS systems using APFS or HFS+ file systems.
date: "2026-07-11T07:36:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - setuptools
  - python
  - macos
  - vulnerability
  - supply-chain
vendors:
  - Python Software Foundation
products:
  - setuptools
affected_os:
  - macOS
cves:
  - id: CVE-2026-59890
    cvss: 6.1
    epss: 0.00269
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59890
---

CVE-2026-59890 details a vulnerability in the `setuptools` Python package, specifically impacting macOS environments utilizing APFS or HFS+ file systems. This flaw allows for a bypass of the `MANIFEST.in` exclusion rules during the creation of source distribution (sdist) packages. The root cause lies in how `setuptools` handles file exclusions in the presence of Unicode normalization collisions (NFC/NFD), which can occur on certain macOS file systems. An attacker could craft file names that, while visually distinct or nominally different, normalize to the same sequence, tricking `setuptools` into either including sensitive files meant to be excluded or excluding legitimate files, potentially leading to supply chain integrity issues or unintended information disclosure within Python projects. This vulnerability highlights the complexities of file system interactions and Unicode handling in software packaging.

## Attack Chain

1. A Python project maintainer uses `setuptools` to create a source distribution (sdist) package for their application on a macOS system formatted with APFS or HFS+.
2. The maintainer defines exclusions in `MANIFEST.in` to prevent sensitive files (e.g., test data, build artifacts, configuration files) from being included in the sdist package.
3. An attacker, aware of the vulnerability, might craft malicious files or manipulate existing file names within the project's source tree.
4. The crafted filenames exploit Unicode normalization differences (NFC/NFD) such that, while they appear unique or different in their raw form, they normalize to the same representation on the macOS file system.
5. When `setuptools` processes the `MANIFEST.in` exclusions, the Unicode normalization collision leads it to incorrectly identify or misinterpret file paths.
6. This misinterpretation results in `setuptools` failing to exclude intended sensitive files, or conversely, inadvertently including malicious files, into the final sdist package.
7. The compromised sdist package is then distributed, containing files that should have been excluded (e.g., sensitive intellectual property, API keys) or potentially containing malicious payloads.
8. Downstream users who install the compromised sdist package unknowingly receive these unexcluded or malicious files, potentially leading to data breaches, system compromise, or supply chain attacks.

## Impact

The primary impact of CVE-2026-59890 is the potential for information disclosure or supply chain integrity compromise in Python projects developed and distributed via `setuptools` on vulnerable macOS systems. Organizations using `setuptools` for packaging applications on macOS with APFS/HFS+ may inadvertently include sensitive project files (e.g., API keys, private certificates, internal documentation, test data) into publicly distributed sdist packages. Conversely, a sophisticated attacker could potentially inject malicious code into a project's sdist by exploiting these normalization collisions, leading to widespread compromise of users who install the affected package. While no specific victim counts are available, any Python project relying on `setuptools` for packaging on the affected macOS environments is at risk.

## Recommendation

* Refer to the official `setuptools` documentation or security advisories for patches addressing CVE-2026-59890 and apply them immediately to all development and build environments.
* Advise developers packaging Python applications on macOS (APFS/HFS+) to be aware of Unicode normalization issues, especially when defining `MANIFEST.in` exclusions.
* Review existing `MANIFEST.in` configurations and the contents of generated sdist packages to ensure no unintended files are included, particularly if operating on affected macOS file systems.
