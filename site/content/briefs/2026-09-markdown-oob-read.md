---
title: Out-of-Bounds Read Vulnerability in 92181 markdown Library
slug: 2026-09-markdown-oob-read
description: An out-of-bounds read vulnerability in the 'lds' function of the 92181 markdown library allows remote attackers to trigger memory access errors via crafted inputs.
date: "2026-09-07T13:36:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:92181:markdown:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve-2026-86303
  - markdown
  - memory-safety
vendors:
  - "92181"
products:
  - markdown (<= 058cab0cb7fb245a0ccc6b8446963ff8d573558f)
cves:
  - id: CVE-2026-86303
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86303
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Software Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade markdown library to commit c000d2f9cf390c315378d3717cf20911cf3e80a6 or later
      owner: Software Engineering
      addresses: CVE-2026-86303
      evidence: A patch should be applied to remediate this issue.
---

A security vulnerability identified as CVE-2026-86303 affects the 92181 markdown library in versions up to commit 058cab0cb7fb245a0ccc6b8446963ff8d573558f. The vulnerability resides within the 'lds' function located in the 'md.c' source file. This issue is categorized as an out-of-bounds read, which can be triggered remotely by providing specially crafted markdown input to an application utilizing this library. Due to the project's rolling release model, specific version numbers are unavailable, making commit hashes the primary identifier for tracking affected and patched states. Exploitation of this vulnerability may lead to crashes or potential information disclosure depending on the implementation context of the library. Developers and security teams are advised to apply the fix provided in commit c000d2f9cf390c315378d3717cf20911cf3e80a6 to remediate the vulnerability.

## Impact

The vulnerability allows remote attackers to cause memory corruption in applications processing untrusted markdown content, potentially resulting in service disruption or exposure of memory contents. Because this library is likely integrated into various upstream applications, the impact depends on the criticality and accessibility of the software consuming the library. Successful exploitation requires the application to process malicious input, but does not rely on local or authenticated access.

## Recommendation

Prioritized remediation for teams integrating the 92181 markdown library:

- Update the library codebase to commit c000d2f9cf390c315378d3717cf20911cf3e80a6 to remediate CVE-2026-86303.
- Audit applications that process externally sourced markdown files to determine if they utilize the affected versions.
- Implement input validation and sanitization for markdown data before passing it to the library to mitigate potential trigger vectors.
